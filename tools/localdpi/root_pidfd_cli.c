#include "root_pidfd.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Deliberately small versioned CLI. A trusted ROOT lifecycle caller must
 * verify the generation and saved record under its lock before invoking it.
 * The helper never reads or deletes lifecycle records or firewall rules. */
static int decimal(const char *s, uint64_t limit, uint64_t *out) {
    if (!s || !*s || (s[0] == '0' && s[1] != '\0')) return 0;
    uint64_t n = 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9') return 0;
        unsigned digit = (unsigned)(*s - '0');
        if (digit > limit || n > (limit - digit) / 10) return 0;
        n = n * 10 + digit;
    }
    *out = n;
    return 1;
}

static int invalid(void) {
    puts("invalid_arguments");
    return 64;
}

static int report(enum dppass_pidfd_result result) {
    switch (result) {
        case DPPASS_PIDFD_EXITED: puts("exited"); return 0;
        case DPPASS_PIDFD_UNSUPPORTED: puts("unsupported"); return 1;
        case DPPASS_PIDFD_UNPROVEN: puts("unproven"); return 2;
        case DPPASS_PIDFD_TIMEOUT: puts("timeout"); return 3;
        default: puts("unproven"); return 2;
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "probe") == 0) {
        enum dppass_pidfd_result result = dppass_pidfd_probe();
        if (result == DPPASS_PIDFD_EXITED) { puts("supported"); return 0; }
        return report(result);
    }
    if (argc == 5 && strcmp(argv[1], "gone") == 0) {
        uint64_t pid, ticks;
        if (!decimal(argv[2], INT32_MAX, &pid) || pid <= 1 ||
            !decimal(argv[3], UINT64_MAX, &ticks) || !dppass_pidfd_valid_boot_id(argv[4]))
            return invalid();
        return report(dppass_pidfd_gone((pid_t)pid, ticks, argv[4]));
    }
    if (argc == 4 && strcmp(argv[1], "absent") == 0) {
        uint64_t pid;
        if (!decimal(argv[2], INT32_MAX, &pid) || pid <= 1 || !dppass_pidfd_valid_boot_id(argv[3]))
            return invalid();
        return report(dppass_pidfd_absent((pid_t)pid, argv[3]));
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("dppass-root-pidfd/1");
        return 0;
    }
    int script;
    if (argc == 7 && strcmp(argv[1], "stop-executable") == 0) script = 0;
    else if (argc == 8 && strcmp(argv[1], "stop-script") == 0) script = 1;
    else return invalid();

    uint64_t pid, ticks, timeout;
    if (!decimal(argv[2], INT32_MAX, &pid) || pid <= 1 ||
        pid == (uint64_t)getpid() ||
        !decimal(argv[3], UINT64_MAX, &ticks) ||
        !dppass_pidfd_valid_boot_id(argv[4]) || !dppass_pidfd_valid_path(argv[5]) ||
        (script && !dppass_pidfd_valid_path(argv[6])) ||
        !decimal(argv[6 + script], 5000, &timeout))
        return invalid();

    enum dppass_pidfd_result result = script
        ? dppass_pidfd_stop_script((pid_t)pid, ticks, argv[4], argv[5], argv[6], (int)timeout)
        : dppass_pidfd_stop_executable((pid_t)pid, ticks, argv[4], argv[5], (int)timeout);
    return report(result);
}
