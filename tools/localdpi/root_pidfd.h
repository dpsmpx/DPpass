#ifndef DPPASS_ROOT_PIDFD_H
#define DPPASS_ROOT_PIDFD_H

#include <stdint.h>
#include <sys/types.h>

enum dppass_pidfd_result {
    DPPASS_PIDFD_EXITED = 0,
    DPPASS_PIDFD_UNSUPPORTED,
    DPPASS_PIDFD_UNPROVEN,
    DPPASS_PIDFD_TIMEOUT
};

/*
 * Experimental Linux primitive. Caller must validate generation and the
 * persisted child record under the lifecycle lock. No metadata is modified.
 * Script mode also requires the exact interpreter executable and argv.
 * No fallback to numeric-PID signaling on unsupported kernels.
 */
enum dppass_pidfd_result dppass_pidfd_stop_executable(
    pid_t pid, uint64_t start_ticks, const char *boot_id,
    const char *executable, int timeout_ms);

/* Interpreter must be its canonical /proc/<pid>/exe path. Script mode
 * only accepts argv = {"sh" or interpreter, script}, with no extras. */
enum dppass_pidfd_result dppass_pidfd_stop_script(
    pid_t pid, uint64_t start_ticks, const char *boot_id,
    const char *interpreter, const char *script, int timeout_ms);

// Probe availability with a self pidfd and signal zero, not TERM.
// EXITED (=0) denotes a successful capability probe here.
enum dppass_pidfd_result dppass_pidfd_probe(void);

// No-signal same-boot absence/death check; caller validates persisted PID,
// generation and boot. A live task, including a reused PID, is unproven.
enum dppass_pidfd_result dppass_pidfd_absent(pid_t pid, const char *boot_id);

#endif
