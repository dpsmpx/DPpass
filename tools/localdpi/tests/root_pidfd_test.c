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

/* Real shell fixture with a ready handshake and blocked builtin read.
 * No subprocess tree is needed; the parent owns and reaps the shell. */
static pid_t script_child(const char *script, int extra_arg, int *input) {
    int ready[2], in[2];
    assert(pipe(ready) == 0 && pipe(in) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(ready[0]);
        close(in[1]);
        assert(dup2(ready[1], STDOUT_FILENO) == STDOUT_FILENO);
        assert(dup2(in[0], STDIN_FILENO) == STDIN_FILENO);
        close(ready[1]);
        close(in[0]);
        if (extra_arg) execl("/bin/sh", "sh", script, "extra", (char *)NULL);
        else execl("/bin/sh", "sh", script, (char *)NULL);
        _exit(127);
    }
    close(ready[1]);
    close(in[0]);
    char marker;
    assert(read(ready[0], &marker, 1) == 1 && marker == 'x');
    close(ready[0]);
    *input = in[1];
    return pid;
}

static void test_script(const char *boot) {
    char script[] = "/tmp/dppass-watchdog-XXXXXX";
    int file = mkstemp(script);
    assert(file >= 0);
    const char body[] = "printf x\nread line\n";
    assert(write(file, body, sizeof(body) - 1) == (ssize_t)(sizeof(body) - 1));
    assert(close(file) == 0);
    char *shell = realpath("/bin/sh", NULL);
    assert(shell);
    int input, status;
    pid_t pid = script_child(script, 0, &input);
    uint64_t ticks = child_ticks(pid);
    char wrong_script[128];
    assert(snprintf(wrong_script, sizeof(wrong_script), "%s-extra", script) < (int)sizeof(wrong_script));
    assert(dppass_pidfd_stop_script(pid, ticks, boot, shell, wrong_script, 100) == DPPASS_PIDFD_UNPROVEN);
    assert_running(pid);
    assert(dppass_pidfd_stop_script(pid, ticks, boot, "/not-the-shell", script, 100) == DPPASS_PIDFD_UNPROVEN);
    assert_running(pid);
    assert(dppass_pidfd_stop_script(pid, ticks + 1, boot, shell, script, 100) == DPPASS_PIDFD_UNPROVEN);
    assert_running(pid);
    assert(dppass_pidfd_stop_script(pid, ticks, boot, shell, NULL, 100) == DPPASS_PIDFD_UNPROVEN);
    assert_running(pid);
    assert(dppass_pidfd_stop_script(pid, ticks, boot, shell, script, 2000) == DPPASS_PIDFD_EXITED);
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
    close(input);

    // A real shell executing the same script with unexpected extra argv
    // is not the recorded watchdog command.
    pid = script_child(script, 1, &input);
    ticks = child_ticks(pid);
    assert(dppass_pidfd_stop_script(pid, ticks, boot, shell, script, 100) == DPPASS_PIDFD_UNPROVEN);
    assert_running(pid);
    assert(write(input, "\n", 1) == 1);
    close(input);
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(unlink(script) == 0);
    free(shell);
}

static void test_argument_validation(void) {
    const char *boot = "01234567-89ab-cdef-0123-456789abcdef";
    assert(dppass_pidfd_valid_boot_id(boot));
    assert(!dppass_pidfd_valid_boot_id(NULL));
    assert(!dppass_pidfd_valid_boot_id(""));
    assert(!dppass_pidfd_valid_boot_id("01234567-89ab-Cdef-0123-456789abcdef"));
    assert(!dppass_pidfd_valid_boot_id("01234567_89ab-cdef-0123-456789abcdef"));
    assert(!dppass_pidfd_valid_boot_id("01234567-89ab-cdef-0123-456789abcdef\n"));
    assert(dppass_pidfd_valid_path("/data/adb/dppass/helper"));
    assert(!dppass_pidfd_valid_path(NULL));
    assert(!dppass_pidfd_valid_path(""));
    assert(!dppass_pidfd_valid_path("/"));
    assert(!dppass_pidfd_valid_path("relative"));
    assert(!dppass_pidfd_valid_path("/bad\npath"));
    assert(!dppass_pidfd_valid_path("/bad\177path"));
    char long_path[4097];
    memset(long_path,'x',sizeof(long_path));
    long_path[0]='/';
    long_path[4096]='\0';
    assert(!dppass_pidfd_valid_path(long_path));
    long_path[4095]='\0';
    assert(dppass_pidfd_valid_path(long_path));
}

static void test_no_signal_proofs(const char *boot, const char *exe) {
    pid_t pid=child(0);
    uint64_t ticks=child_ticks(pid);
    assert(dppass_pidfd_absent(pid,boot)==DPPASS_PIDFD_UNPROVEN);
    assert(dppass_pidfd_gone(pid,ticks,boot)==DPPASS_PIDFD_UNPROVEN);
    assert(dppass_pidfd_gone(pid,ticks+1,boot)==DPPASS_PIDFD_EXITED);
    assert_running(pid);
    assert(dppass_pidfd_gone(pid,ticks,"bad")==DPPASS_PIDFD_UNPROVEN);
    assert(dppass_pidfd_absent(pid,NULL)==DPPASS_PIDFD_UNPROVEN);
    assert(dppass_pidfd_stop_executable(pid,ticks,boot,"/",100)==DPPASS_PIDFD_UNPROVEN);
    assert(dppass_pidfd_stop_script(pid,ticks,boot,exe,"/bad\nscript",100)==DPPASS_PIDFD_UNPROVEN);
    assert_running(pid);
    assert(kill(pid,SIGTERM)==0);
    int status;
    assert(waitpid(pid,&status,0)==pid);
    assert(WIFSIGNALED(status) && WTERMSIG(status)==SIGTERM);
    // A numeric PID could be reused after reaping. gone proves absence or
    // different start ticks; absent intentionally makes no reuse claim.
    assert(dppass_pidfd_gone(pid,ticks,boot)==DPPASS_PIDFD_EXITED);
}

static void test_namespace_status(void) {
    assert(dppass_pidfd_namespace_status("Name:\tfixture\nNSpid:\t123\nThreads:\t1\n", 123));
    assert(dppass_pidfd_namespace_status("NSpid: 123\t", 123));
    assert(!dppass_pidfd_namespace_status("NSpid:\t456\t123\n", 123));
    assert(!dppass_pidfd_namespace_status("NSpid:\t123\t123\n", 123));
    assert(!dppass_pidfd_namespace_status("NSpid:\t1234\n", 123));
    assert(!dppass_pidfd_namespace_status("NSpid:\t0123\n", 123));
    assert(!dppass_pidfd_namespace_status("NSpid:123\n", 123));
    assert(!dppass_pidfd_namespace_status("NSpid:\t123\nNSpid:\t123\n", 123));
    assert(!dppass_pidfd_namespace_status("Pid:\t123\n", 123));
    assert(!dppass_pidfd_namespace_status("Name:\tNSpid: 123\n", 123));
    assert(!dppass_pidfd_namespace_status(NULL, 123));
}

int main(void) {
    test_namespace_status();
    test_argument_validation();
    assert(dppass_pidfd_probe() == DPPASS_PIDFD_EXITED);
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
    assert(dppass_pidfd_stop_executable(getpid(), child_ticks(getpid()), boot, exe, 100) == DPPASS_PIDFD_UNPROVEN);
    test_no_signal_proofs(boot,exe);

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
    test_script(boot);
    puts("ROOT pidfd executable/script identity and exit tests passed");
    return 0;
}
