#define _GNU_SOURCE
#include "root_pidfd.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t child_ticks(pid_t pid) {
    char path[64], line[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *f = fopen(path, "r");
    assert(f);
    assert(fgets(line, sizeof(line), f));
    assert(fclose(f) == 0);
    char *end = strrchr(line, ')'), *save = NULL;
    assert(end);
    char *token = strtok_r(end + 2, " ", &save);
    for (int field = 4; field <= 22; ++field) {
        token = strtok_r(NULL, " ", &save);
        assert(token);
    }
    return strtoull(token, NULL, 10);
}

static pid_t child(int ignore_term) {
    int ready[2];
    assert(pipe(ready) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(ready[0]);
        assert(signal(SIGTERM, ignore_term ? SIG_IGN : SIG_DFL) != SIG_ERR);
        assert(write(ready[1], "x", 1) == 1);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    char marker;
    assert(read(ready[0], &marker, 1) == 1);
    close(ready[0]);
    return pid;
}

static void assert_running(pid_t pid) {
    int status;
    assert(waitpid(pid, &status, WNOHANG) == 0);
}

int main(void) {
    char boot[64], exe[4096];
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    assert(f && fgets(boot, sizeof(boot), f));
    assert(fclose(f) == 0);
    boot[strcspn(boot, "\n")] = '\0';
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    assert(len > 0 && (size_t)len < sizeof(exe) - 1);
    exe[len] = '\0';
    assert(dppass_pidfd_stop_executable(1, 0, boot, exe, 100) == DPPASS_PIDFD_UNPROVEN);
    assert(dppass_pidfd_stop_executable(getpid(), 0, boot, exe, 5001) == DPPASS_PIDFD_UNPROVEN);

    pid_t pid = child(0);
    uint64_t ticks = child_ticks(pid);
    enum dppass_pidfd_result wrong_ticks =
        dppass_pidfd_stop_executable(pid, ticks + 1, boot, exe, 100);
    assert(wrong_ticks == DPPASS_PIDFD_UNPROVEN || wrong_ticks == DPPASS_PIDFD_UNSUPPORTED);
    assert_running(pid);
    enum dppass_pidfd_result wrong_exe =
        dppass_pidfd_stop_executable(pid, ticks, boot, "/not-the-child", 100);
    assert(wrong_exe == DPPASS_PIDFD_UNPROVEN || wrong_exe == DPPASS_PIDFD_UNSUPPORTED);
    assert_running(pid);
    char wrong_boot[64];
    strcpy(wrong_boot, boot);
    wrong_boot[0] = boot[0] == '0' ? '1' : '0';
    enum dppass_pidfd_result wrong =
        dppass_pidfd_stop_executable(pid, ticks, wrong_boot, exe, 100);
    assert(wrong == DPPASS_PIDFD_UNPROVEN || wrong == DPPASS_PIDFD_UNSUPPORTED);
    assert_running(pid);

    enum dppass_pidfd_result result = dppass_pidfd_stop_executable(pid, ticks, boot, exe, 2000);
    if (result == DPPASS_PIDFD_UNSUPPORTED) {
        // Host CI requires real pidfd support; do not silently skip coverage.
        assert(kill(pid, SIGKILL) == 0);
        assert(waitpid(pid, NULL, 0) == pid);
        fputs("pidfd unavailable: native positive test cannot run\n", stderr);
        return 1;
    }
    int status;
    assert(result == DPPASS_PIDFD_EXITED);
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);

    // A TERM-resistant fixture proves that a successful syscall is not
    // equivalent to confirmed process exit. No escalation by the helper.
    pid = child(1);
    ticks = child_ticks(pid);
    assert(dppass_pidfd_stop_executable(pid, ticks, boot, exe, 100) == DPPASS_PIDFD_TIMEOUT);
    assert_running(pid);
    // Only the test owns this unreaped child; explicit fixture teardown.
    assert(kill(pid, SIGKILL) == 0);
    assert(waitpid(pid, NULL, 0) == pid);
    puts("ROOT pidfd identity and exit tests passed");
    return 0;
}
