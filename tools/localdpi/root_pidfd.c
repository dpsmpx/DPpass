#define _GNU_SOURCE
#include "root_pidfd.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
static int read_text(const char *path, char *buf, size_t capacity) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0;
    while (used < capacity - 1) {
        ssize_t n = read(fd, buf + used, capacity - 1 - used);
        if (n < 0) { close(fd); return -1; }
        if (n == 0) break;
        used += (size_t)n;
    }
    close(fd);
    if (used == capacity - 1) return -1;
    buf[used] = '\0';
    return 0;
}

static int valid_boot_id(const char *s) {
    if (strlen(s) != 36) return 0;
    for (size_t i = 0; i < 36; ++i) {
        char ch = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (ch != '-') return 0;
        } else if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int boot_matches(const char *expected) {
    char actual[64];
    if (!valid_boot_id(expected) ||
        read_text("/proc/sys/kernel/random/boot_id", actual, sizeof(actual)) != 0)
        return 0;
    size_t len = strlen(actual);
    if (len && actual[len - 1] == '\n') actual[len - 1] = '\0';
    return valid_boot_id(actual) && strcmp(actual, expected) == 0;
}

static int start_matches(pid_t pid, uint64_t expected) {
    char path[64], stat[4096], prefix[32];
    if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) >= (int)sizeof(path) ||
        snprintf(prefix, sizeof(prefix), "%ld (", (long)pid) >= (int)sizeof(prefix) ||
        read_text(path, stat, sizeof(stat)) != 0 ||
        strncmp(stat, prefix, strlen(prefix)) != 0)
        return 0;
    char *end = strrchr(stat, ')');
    if (!end || end[1] != ' ') return 0;
    char *save = NULL;
    char *token = strtok_r(end + 2, " \t\n", &save);
    if (!token || strlen(token) != 1 || !strchr("RSDTtIWP", token[0])) return 0;
    for (int field = 4; field <= 22; ++field) {
        token = strtok_r(NULL, " \t\n", &save);
        if (!token) return 0;
    }
    if (!*token || strspn(token, "0123456789") != strlen(token)) return 0;
    errno = 0;
    unsigned long long ticks = strtoull(token, NULL, 10);
    return errno == 0 && ticks == expected;
}

static int executable_matches(pid_t pid, const char *expected) {
    char path[64], actual[4096];
    if (snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid) >= (int)sizeof(path))
        return 0;
    ssize_t n = readlink(path, actual, sizeof(actual) - 1);
    if (n < 0 || (size_t)n == sizeof(actual) - 1) return 0;
    actual[n] = '\0';
    return strcmp(actual, expected) == 0;
}

/* POLLIN means the task exited, POLLHUP means it was reaped. Both refer
 * to the pinned task, not whatever later occupies the numeric PID. */
static int exited(int fd, int timeout_ms) {
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    int result = poll(&p, 1, timeout_ms);
    if (result < 0) return -1;
    if (result == 0) return 0;
    if (p.revents & (POLLERR | POLLNVAL)) return -1;
    return (p.revents & (POLLIN | POLLHUP)) ? 1 : -1;
}
#endif

enum dppass_pidfd_result dppass_pidfd_stop_executable(
    pid_t pid, uint64_t start_ticks, const char *boot_id,
    const char *executable, int timeout_ms) {
    if (pid <= 1 || !boot_id || !executable || executable[0] != '/' ||
        timeout_ms < 0 || timeout_ms > 5000)
        return DPPASS_PIDFD_UNPROVEN;
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    // Pin the task before reading any numeric-PID proc identity.
    int fd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (fd < 0)
        return errno == ENOSYS ? DPPASS_PIDFD_UNSUPPORTED : DPPASS_PIDFD_UNPROVEN;
    enum dppass_pidfd_result result = DPPASS_PIDFD_UNPROVEN;
    if (!boot_matches(boot_id) || !start_matches(pid, start_ticks) ||
        !executable_matches(pid, executable) || !start_matches(pid, start_ticks))
        goto done;
    // If the original task exited while proc was read, those reads may
    // refer to a reused PID. Never signal or report validated ownership.
    if (exited(fd, 0) != 0) goto done;
    if (syscall(SYS_pidfd_send_signal, fd, SIGTERM, NULL, 0) < 0) {
        int error = errno;
        if (error == ENOSYS) result = DPPASS_PIDFD_UNSUPPORTED;
        else if (error == ESRCH && exited(fd, 0) == 1) result = DPPASS_PIDFD_EXITED;
        goto done;
    }
    int status = exited(fd, timeout_ms);
    if (status == 1) result = DPPASS_PIDFD_EXITED;
    else if (status == 0) result = DPPASS_PIDFD_TIMEOUT;
done:
    close(fd);
    return result;
#else
    (void)start_ticks;
    return DPPASS_PIDFD_UNSUPPORTED;
#endif
}
