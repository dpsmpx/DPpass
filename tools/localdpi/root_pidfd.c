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
#include <sys/vfs.h>
#include <unistd.h>

#if defined(DPPASS_REQUIRE_PIDFD_SYSCALLS) && (!defined(SYS_pidfd_open) || !defined(SYS_pidfd_send_signal))
#error "NDK headers must expose both pidfd syscall numbers"
#endif

/* NSpid is relative to the PID namespace of the procfs mount. A
 * single value equal to getpid() establishes a same-namespace view.
 * Reject nested views even if the outer and inner numeric PIDs coincide. */
int dppass_pidfd_namespace_status(const char *status, pid_t pid) {
    if (!status || pid <= 0) return 0;
    char expected[32];
    int length = snprintf(expected, sizeof(expected), "%ld", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(expected)) return 0;
    int found = 0;
    for (const char *line = status; *line;) {
        const char *end = strchr(line, '\n');
        if (!end) end = line + strlen(line);
        if ((size_t)(end - line) >= 6 && memcmp(line, "NSpid:", 6) == 0) {
            if (found) return 0;
            const char *p = line + 6;
            if (p == end || (*p != ' ' && *p != '\t')) return 0;
            while (p < end && (*p == ' ' || *p == '\t')) ++p;
            if ((size_t)(end - p) < (size_t)length ||
                memcmp(p, expected, (size_t)length) != 0) return 0;
            p += length;
            while (p < end && (*p == ' ' || *p == '\t')) ++p;
            if (p != end) return 0;
            found = 1;
        }
        line = *end ? end + 1 : end;
    }
    return found;
}

int dppass_pidfd_valid_boot_id(const char *s) {
    if (!s || strlen(s) != 36) return 0;
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

int dppass_pidfd_valid_path(const char *s) {
    if (!s || s[0] != '/' || s[1] == '\0' || strlen(s) > 4095) return 0;
    for (; *s; ++s) {
        unsigned char ch = (unsigned char)*s;
        if (ch < 32 || ch == 127) return 0;
    }
    return 1;
}

#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
static ssize_t read_bytes(const char *path, char *buf, size_t capacity) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0;
    while (used < capacity - 1) {
        ssize_t n = read(fd, buf + used, capacity - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { close(fd); return -1; }
        if (n == 0) break;
        used += (size_t)n;
    }
    close(fd);
    if (used == capacity - 1) return -1;
    buf[used] = '\0';
    return (ssize_t)used;
}

static int read_text(const char *path, char *buf, size_t capacity) {
    ssize_t n = read_bytes(path, buf, capacity);
    if (n < 0 || memchr(buf, '\0', (size_t)n)) return -1;
    return 0;
}

/* The caller uses a trusted host /proc, not an arbitrary filesystem.
 * Check the procfs superblock, self link and namespace-relative PID list
 * before interpreting any numeric PID or claiming ESRCH proves absence.
 * An inaccessible or missing NSpid field fails closed. */
static int proc_namespace_matches(void) {
    struct statfs fs;
    if (statfs("/proc", &fs) != 0 || (unsigned long)fs.f_type != 0x9fa0UL)
        return 0;
    pid_t pid = getpid();
    char expected[32], actual[64], status[16384];
    int length = snprintf(expected, sizeof(expected), "%ld", (long)pid);
    ssize_t n = readlink("/proc/self", actual, sizeof(actual));
    if (length <= 0 || (size_t)length >= sizeof(expected) ||
        n != (ssize_t)length || memcmp(actual, expected, (size_t)length) != 0)
        return 0;
    return read_text("/proc/self/status", status, sizeof(status)) == 0 &&
        dppass_pidfd_namespace_status(status, pid);
}

static int boot_matches(const char *expected) {
    char actual[64];
    if (!dppass_pidfd_valid_boot_id(expected) ||
        read_text("/proc/sys/kernel/random/boot_id", actual, sizeof(actual)) != 0)
        return 0;
    size_t len = strlen(actual);
    if (len && actual[len - 1] == '\n') actual[len - 1] = '\0';
    return dppass_pidfd_valid_boot_id(actual) && strcmp(actual, expected) == 0;
}

static int read_start_ticks(pid_t pid, uint64_t *value) {
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
    if (!token || strlen(token) != 1 || !strchr("RSDTtIWPZXx", token[0])) return 0;
    for (int field = 4; field <= 22; ++field) {
        token = strtok_r(NULL, " \t\n", &save);
        if (!token) return 0;
    }
    if (!*token || strspn(token, "0123456789") != strlen(token)) return 0;
    errno = 0;
    unsigned long long ticks = strtoull(token, NULL, 10);
    if (errno != 0) return 0;
    *value = (uint64_t)ticks;
    return 1;
}

static int start_matches(pid_t pid, uint64_t expected) {
    uint64_t actual;
    return read_start_ticks(pid, &actual) && actual == expected;
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

/* The ROOT watchdog is launched as exactly sh /absolute/path/to/script.
 * Match the interpreter executable AND the two complete NUL-delimited argv
 * entries; a substring, extra argument or truncated record cannot match. */
static int script_matches(pid_t pid, const char *interpreter, const char *script) {
    char path[64], argv[8192];
    if (snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid) >= (int)sizeof(path))
        return 0;
    ssize_t n = read_bytes(path, argv, sizeof(argv));
    if (n <= 0 || argv[n - 1] != '\0') return 0;
    const char *end = memchr(argv, '\0', (size_t)n);
    if (!end || (strcmp(argv, "sh") != 0 && strcmp(argv, interpreter) != 0))
        return 0;
    size_t remaining = (size_t)n - (size_t)(end + 1 - argv);
    const char *arg = end + 1;
    return remaining == strlen(script) + 1 && memcmp(arg, script, remaining) == 0;
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

static enum dppass_pidfd_result stop_child(
    pid_t pid, uint64_t start_ticks, const char *boot_id,
    const char *executable, const char *script, int timeout_ms) {
    if (pid <= 1 || pid == getpid() || !dppass_pidfd_valid_boot_id(boot_id) ||
        !dppass_pidfd_valid_path(executable) ||
        (script && !dppass_pidfd_valid_path(script)) || timeout_ms < 0 || timeout_ms > 5000)
        return DPPASS_PIDFD_UNPROVEN;
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    if (!proc_namespace_matches()) return DPPASS_PIDFD_UNPROVEN;
    // Pin the task before reading any numeric-PID proc identity.
    int fd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (fd < 0)
        return errno == ENOSYS ? DPPASS_PIDFD_UNSUPPORTED : DPPASS_PIDFD_UNPROVEN;
    enum dppass_pidfd_result result = DPPASS_PIDFD_UNPROVEN;
    if (!boot_matches(boot_id) || !start_matches(pid, start_ticks) ||
        !executable_matches(pid, executable) ||
        (script && !script_matches(pid, executable, script)) ||
        !start_matches(pid, start_ticks) ||
        !executable_matches(pid, executable) ||
        (script && !script_matches(pid, executable, script)))
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

enum dppass_pidfd_result dppass_pidfd_stop_executable(
    pid_t pid, uint64_t start_ticks, const char *boot_id,
    const char *executable, int timeout_ms) {
    return stop_child(pid, start_ticks, boot_id, executable, NULL, timeout_ms);
}

enum dppass_pidfd_result dppass_pidfd_stop_script(
    pid_t pid, uint64_t start_ticks, const char *boot_id,
    const char *interpreter, const char *script, int timeout_ms) {
    if (!script) return DPPASS_PIDFD_UNPROVEN;
    return stop_child(pid, start_ticks, boot_id, interpreter, script, timeout_ms);
}

enum dppass_pidfd_result dppass_pidfd_probe(void) {
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    if (!proc_namespace_matches()) return DPPASS_PIDFD_UNPROVEN;
    int fd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (fd < 0) return errno == ENOSYS ? DPPASS_PIDFD_UNSUPPORTED : DPPASS_PIDFD_UNPROVEN;
    // Signal zero checks availability/permission without delivering a signal.
    int status = (int)syscall(SYS_pidfd_send_signal, fd, 0, NULL, 0);
    int error = errno;
    close(fd);
    if (status == 0) return DPPASS_PIDFD_EXITED;
    return error == ENOSYS ? DPPASS_PIDFD_UNSUPPORTED : DPPASS_PIDFD_UNPROVEN;
#else
    return DPPASS_PIDFD_UNSUPPORTED;
#endif
}

enum dppass_pidfd_result dppass_pidfd_absent(pid_t pid, const char *boot_id) {
    if (pid <= 1 || !dppass_pidfd_valid_boot_id(boot_id)) return DPPASS_PIDFD_UNPROVEN;
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    if (!proc_namespace_matches() || !boot_matches(boot_id)) return DPPASS_PIDFD_UNPROVEN;
    int fd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (fd < 0) {
        if (errno == ESRCH) return DPPASS_PIDFD_EXITED;
        return errno == ENOSYS ? DPPASS_PIDFD_UNSUPPORTED : DPPASS_PIDFD_UNPROVEN;
    }
    int status = exited(fd, 0);
    close(fd);
    return status == 1 ? DPPASS_PIDFD_EXITED : DPPASS_PIDFD_UNPROVEN;
#else
    return DPPASS_PIDFD_UNSUPPORTED;
#endif
}


/* Positive no-signal proof for a persisted same-boot identity. Pin the
 * current task before inspecting its start ticks. A live task with
 * different ticks cannot be the recorded task. Ambiguous proc data stays
 * unproven. */
enum dppass_pidfd_result dppass_pidfd_gone(pid_t pid, uint64_t ticks, const char *boot_id) {
    if (pid <= 1 || !dppass_pidfd_valid_boot_id(boot_id)) return DPPASS_PIDFD_UNPROVEN;
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    if (!proc_namespace_matches() || !boot_matches(boot_id)) return DPPASS_PIDFD_UNPROVEN;
    int fd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (fd < 0) {
        if (errno == ESRCH) return DPPASS_PIDFD_EXITED;
        return errno == ENOSYS ? DPPASS_PIDFD_UNSUPPORTED : DPPASS_PIDFD_UNPROVEN;
    }
    enum dppass_pidfd_result result = DPPASS_PIDFD_UNPROVEN;
    int first = exited(fd, 0);
    if (first == 1) result = DPPASS_PIDFD_EXITED;
    else if (first == 0) {
        uint64_t actual;
        int known = read_start_ticks(pid, &actual);
        int last = exited(fd, 0);
        if (last == 1 || (last == 0 && known && actual != ticks))
            result = DPPASS_PIDFD_EXITED;
    }
    close(fd);
    return result;
#else
    (void)ticks;
    return DPPASS_PIDFD_UNSUPPORTED;
#endif
}
