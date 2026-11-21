// Процессы и псевдотерминал Linux-среды в приложении (D-75, шаг 3): в ART
// нет ProcessHandle, а у java.lang.Process — ни номера процесса, ни своего
// сеанса, ни псевдотерминала. Логика остановки — в Kotlin
// (execution.linux.NativeProcessHost), здесь — только системные вызовы.
//
// Каждый процесс — лидер своего сеанса (setsid): по сеансу находятся и
// потомки, ушедшие в фон. Строки приходят байтами UTF-8 из Kotlin: JNI
// отдаёт строки в «modified UTF-8», и знаки вне BMP исказились бы.
//
// Между fork и exec в дочернем процессе — только вызовы, безопасные после
// fork в многопоточном процессе (async-signal-safe): всё выделено заранее.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define CHUNK 8192

static void free_strings(char **v) {
    if (v == NULL) return;
    for (char **p = v; *p != NULL; p++) free(*p);
    free(v);
}

static char *bytes_to_string(JNIEnv *env, jbyteArray bytes) {
    jsize n = (*env)->GetArrayLength(env, bytes);
    char *s = malloc((size_t) n + 1);
    if (s == NULL) return NULL;
    (*env)->GetByteArrayRegion(env, bytes, 0, n, (jbyte *) s);
    s[n] = '\0';
    return s;
}

// Массив byte[] → массив строк C с NULL в конце.
static char **to_strings(JNIEnv *env, jobjectArray arr) {
    jsize n = (*env)->GetArrayLength(env, arr);
    char **v = calloc((size_t) n + 1, sizeof(char *));
    if (v == NULL) return NULL;
    for (jsize i = 0; i < n; i++) {
        jbyteArray item = (jbyteArray) (*env)->GetObjectArrayElement(env, arr, i);
        v[i] = bytes_to_string(env, item);
        (*env)->DeleteLocalRef(env, item);
        if (v[i] == NULL) {
            free_strings(v);
            return NULL;
        }
    }
    return v;
}

static void close_quietly(int fd) {
    if (fd >= 0) close(fd);
}

// Отказ в дочернем процессе: errno — родителю по каналу отчёта, выход 127.
static void child_fail(int report) {
    int e = errno;
    ssize_t ignored = write(report, &e, sizeof e);
    (void) ignored;
    _exit(127);
}

// Закрыть унаследованные дескрипторы с 3 и выше, кроме канала отчёта (он закроется при exec сам).
static void close_inherited(int keep) {
#ifdef __NR_close_range
    if (keep > 3) syscall(__NR_close_range, 3u, (unsigned) keep - 1, 0u);
    if (syscall(__NR_close_range, (unsigned) keep + 1, ~0u, 0u) == 0) return;
#endif
    for (int fd = 3; fd < 65536; fd++) {
        if (fd != keep) close(fd);
    }
}

/*
 * Запустить argv[0] (полный путь) с окружением envp в каталоге cwd.
 * cols > 0 и rows > 0 — на псевдотерминале. fds получает: [0] — запись во
 * вход процесса, [1] — чтение вывода, [2] — чтение ошибок (у
 * псевдотерминала -1). Итог — номер процесса или -errno.
 */
JNIEXPORT jint JNICALL
Java_com_dpsmpx_dpai_android_linux_NativeCalls_spawn(JNIEnv *env, jclass cls, jobjectArray jargv, jobjectArray jenv,
                                                      jbyteArray jcwd, jint cols, jint rows, jintArray jfds) {
    (void) cls;
    int pty = cols > 0 && rows > 0;
    int rc = -ENOMEM;
    char **argv = to_strings(env, jargv);
    char **envp = to_strings(env, jenv);
    char *cwd = jcwd != NULL ? bytes_to_string(env, jcwd) : NULL;
    int report[2] = {-1, -1}, in[2] = {-1, -1}, out[2] = {-1, -1}, err[2] = {-1, -1};
    int master = -1;
    char slave[128];
    pid_t pid = -1;
    jint fds[3];
    if (argv == NULL || argv[0] == NULL || envp == NULL || (jcwd != NULL && cwd == NULL)) goto done;
    if (pipe2(report, O_CLOEXEC) < 0) goto fail;
    if (pty) {
        master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0 || ptsname_r(master, slave, sizeof slave) != 0) goto fail;
        struct winsize ws = {.ws_row = (unsigned short) rows, .ws_col = (unsigned short) cols};
        if (ioctl(master, TIOCSWINSZ, &ws) < 0) goto fail;
    } else if (pipe2(in, O_CLOEXEC) < 0 || pipe2(out, O_CLOEXEC) < 0 || pipe2(err, O_CLOEXEC) < 0) {
        goto fail;
    }
    pid = fork();
    if (pid < 0) goto fail;
    if (pid == 0) {
        // Сигналы — по умолчанию: игнорируемые (SIGPIPE у ART) и маска наследуются через exec.
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        struct sigaction dfl;
        memset(&dfl, 0, sizeof dfl);
        dfl.sa_handler = SIG_DFL;
        for (int s = 1; s < NSIG; s++) sigaction(s, &dfl, NULL);
        if (setsid() < 0) child_fail(report[1]);
        if (pty) {
            // Лидер сеанса без управляющего терминала: открытый ведомый становится им.
            int fd = open(slave, O_RDWR);
            if (fd < 0) child_fail(report[1]);
            ioctl(fd, TIOCSCTTY, 0);
            struct termios t;
            if (tcgetattr(fd, &t) == 0) {
                t.c_iflag |= IUTF8;
                t.c_cc[VERASE] = 0x7f;
                tcsetattr(fd, TCSANOW, &t);
            }
            if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) child_fail(report[1]);
        } else if (dup2(in[0], 0) < 0 || dup2(out[1], 1) < 0 || dup2(err[1], 2) < 0) {
            child_fail(report[1]);
        }
        close_inherited(report[1]);
        if (cwd != NULL && chdir(cwd) < 0) child_fail(report[1]);
        execve(argv[0], argv, envp);
        child_fail(report[1]);
    }
    close(report[1]);
    report[1] = -1;
    int child_errno = 0;
    ssize_t n;
    do {
        n = read(report[0], &child_errno, sizeof child_errno);
    } while (n < 0 && errno == EINTR);
    if (n == (ssize_t) sizeof child_errno) {
        // exec не случился: процесс уже вышел с кодом 127 — забрать его и вернуть причину.
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        rc = -child_errno;
        goto done;
    }
    if (pty) {
        int writer = fcntl(master, F_DUPFD_CLOEXEC, 0);
        if (writer < 0) {
            // Процесс запущен, а писать ему некуда: остановить и отказать.
            int e = errno;
            kill(-pid, SIGKILL);
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
            errno = e;
            goto fail;
        }
        fds[0] = writer;
        fds[1] = master;
        fds[2] = -1;
        master = -1;
    } else {
        fds[0] = in[1];
        fds[1] = out[0];
        fds[2] = err[0];
        in[1] = out[0] = err[0] = -1;
    }
    (*env)->SetIntArrayRegion(env, jfds, 0, 3, fds);
    rc = pid;
    goto done;
fail:
    rc = -errno;
done:
    close_quietly(report[0]);
    close_quietly(report[1]);
    close_quietly(in[0]);
    close_quietly(in[1]);
    close_quietly(out[0]);
    close_quietly(out[1]);
    close_quietly(err[0]);
    close_quietly(err[1]);
    close_quietly(master);
    free_strings(argv);
    free_strings(envp);
    free(cwd);
    return rc;
}

// Ждать выхода процесса и забрать его: код, 128 + сигнал или -errno.
JNIEXPORT jint JNICALL
Java_com_dpsmpx_dpai_android_linux_NativeCalls_waitFor(JNIEnv *env, jclass cls, jint pid) {
    (void) env;
    (void) cls;
    int status;
    pid_t r;
    do {
        r = waitpid(pid, &status, 0);
    } while (r < 0 && errno == EINTR);
    if (r < 0) return -errno;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -EINVAL;
}

JNIEXPORT jint JNICALL
Java_com_dpsmpx_dpai_android_linux_NativeCalls_kill(JNIEnv *env, jclass cls, jint pid, jint sig) {
    (void) env;
    (void) cls;
    return kill(pid, sig) == 0 ? 0 : -errno;
}

JNIEXPORT jint JNICALL
Java_com_dpsmpx_dpai_android_linux_NativeCalls_resize(JNIEnv *env, jclass cls, jint fd, jint cols, jint rows) {
    (void) env;
    (void) cls;
    struct winsize ws = {.ws_row = (unsigned short) rows, .ws_col = (unsigned short) cols};
    return ioctl(fd, TIOCSWINSZ, &ws) == 0 ? 0 : -errno;
}

// Прочитать до len байт: число, 0 — конец (у псевдотерминала конец — EIO), -errno.
JNIEXPORT jint JNICALL
Java_com_dpsmpx_dpai_android_linux_NativeCalls_read(JNIEnv *env, jclass cls, jint fd, jbyteArray buf, jint off, jint len) {
    (void) cls;
    char tmp[CHUNK];
    ssize_t n;
    do {
        n = read(fd, tmp, len < CHUNK ? (size_t) len : CHUNK);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return errno == EIO ? 0 : -errno;
    (*env)->SetByteArrayRegion(env, buf, off, (jsize) n, (const jbyte *) tmp);
    return (jint) n;
}

// Записать len байт целиком: len или -errno.
JNIEXPORT jint JNICALL
Java_com_dpsmpx_dpai_android_linux_NativeCalls_write(JNIEnv *env, jclass cls, jint fd, jbyteArray buf, jint off, jint len) {
    (void) cls;
    char tmp[CHUNK];
    jint done = 0;
    while (done < len) {
        jint part = len - done < CHUNK ? len - done : CHUNK;
        (*env)->GetByteArrayRegion(env, buf, off + done, part, (jbyte *) tmp);
        jint sent = 0;
        while (sent < part) {
            ssize_t n = write(fd, tmp + sent, (size_t) (part - sent));
            if (n < 0) {
                if (errno == EINTR) continue;
                return -errno;
            }
            sent += (jint) n;
        }
        done += part;
    }
    return len;
}

JNIEXPORT jint JNICALL
Java_com_dpsmpx_dpai_android_linux_NativeCalls_close(JNIEnv *env, jclass cls, jint fd) {
    (void) env;
    (void) cls;
    return close(fd) == 0 ? 0 : -errno;
}

JNIEXPORT jstring JNICALL
Java_com_dpsmpx_dpai_android_linux_NativeCalls_describe(JNIEnv *env, jclass cls, jint error) {
    (void) cls;
    return (*env)->NewStringUTF(env, strerror(error));
}
