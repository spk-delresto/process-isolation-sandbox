#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>

#define SOCK_PATH  "/tmp/auth_backend.sock"
#define MAX_USER   64
#define MAX_PASS   128

static void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

/* Read a password from the controlling terminal without echoing it. */
static int read_password(char *buf, size_t buflen) {
    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        /* Not a TTY (e.g. piped input for automated testing) - fall back
           to a plain read so the program still works non-interactively. */
        if (!fgets(buf, buflen, stdin)) return -1;
        buf[strcspn(buf, "\n")] = 0;
        return 0;
    }
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    int ok = fgets(buf, buflen, stdin) != NULL;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); /* always restore terminal */
    printf("\n");

    if (!ok) return -1;
    buf[strcspn(buf, "\n")] = 0;
    return 0;
}

int main(int argc, char **argv) {
    char user[MAX_USER] = {0};
    char pass[MAX_PASS] = {0};

    fprintf(stderr, "[frontend] running as uid=%d (unprivileged, by design)\n", getuid());

    if (argc >= 3) {
        /* Non-interactive mode for scripted testing: frontend <user> <pass> */
        strncpy(user, argv[1], sizeof(user) - 1);
        strncpy(pass, argv[2], sizeof(pass) - 1);
    } else {
        printf("Username: ");
        fflush(stdout);
        if (!fgets(user, sizeof(user), stdin)) return EXIT_FAILURE;
        user[strcspn(user, "\n")] = 0;

        printf("Password: ");
        fflush(stdout);
        if (read_password(pass, sizeof(pass)) != 0) return EXIT_FAILURE;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return EXIT_FAILURE; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect (is backend running?)");
        secure_zero(pass, sizeof(pass));
        close(fd);
        return EXIT_FAILURE;
    }

    char msg[MAX_USER + MAX_PASS + 2];
    int len = snprintf(msg, sizeof(msg), "%s\x01%s", user, pass);

    if (write(fd, msg, len) != len) {
        perror("write");
    }

    /* Wipe local copies immediately after transmission. */
    secure_zero(pass, sizeof(pass));
    secure_zero(msg, sizeof(msg));

    char reply[64] = {0};
    ssize_t n = read(fd, reply, sizeof(reply) - 1);
    close(fd);

    if (n <= 0) {
        fprintf(stderr, "[frontend] no response from backend\n");
        return EXIT_FAILURE;
    }
    reply[n] = 0;
    printf("Result: %s", reply);

    int allowed = strncmp(reply, "ALLOW", 5) == 0;
    secure_zero(user, sizeof(user));
    return allowed ? EXIT_SUCCESS : EXIT_FAILURE;
}
