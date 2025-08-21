#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include "nk/daemon.h"

static bool g_is_daemon;

void nk_set_is_daemon(void)
{
    g_is_daemon = true;
}

void nk_daemonize(void)
{
    if (!g_is_daemon) return;
    pid_t c = fork();
    if (c) exit(0);
    setsid();
    c = fork();
    if (c) exit(0);
}

void __attribute__((format (printf, 2, 3))) nk_log(int prio, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    if (g_is_daemon) {
        vsyslog(prio, fmt, args);
    } else {
        vdprintf(2, fmt, args);
    }
    va_end(args);
}
