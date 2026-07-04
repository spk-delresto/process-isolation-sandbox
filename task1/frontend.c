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
