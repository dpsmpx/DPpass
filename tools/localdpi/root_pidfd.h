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
 * Only a verified executable is supported; script identity is not yet handled.
 * No fallback to numeric-PID signaling on unsupported kernels.
 */
enum dppass_pidfd_result dppass_pidfd_stop_executable(
    pid_t pid, uint64_t start_ticks, const char *boot_id,
    const char *executable, int timeout_ms);

#endif
