#ifndef NK_DAEMON_H_
#define NK_DAEMON_H_

#include <syslog.h>

void nk_set_is_daemon(void);
void nk_daemonize(void);
void nk_log(int prio, const char *fmt, ...) __attribute__((format (printf, 2, 3)));

#endif
