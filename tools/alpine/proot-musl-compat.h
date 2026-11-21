/*
 * Совместимость с musl для proot-форка Termux (D-115, tools/linux/build-proot.sh).
 * Форк собирают NDK под bionic; под musl не хватает двух имён из glibc и bionic.
 * Код proot не меняется: файл подключается ко всем единицам ключом -include.
 */
#ifndef __ASSEMBLER__
#include <errno.h>

/* msgrcv(2): флаг ядра Linux (include/uapi/linux/msg.h), в заголовках musl его нет. */
#ifndef MSG_COPY
#define MSG_COPY 040000
#endif

/* Повтор вызова, прерванного сигналом, — как в glibc и bionic. */
#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(e) ({ long _r; do _r = (long)(e); while (_r == -1L && errno == EINTR); _r; })
#endif

#endif /* __ASSEMBLER__ */
