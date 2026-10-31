/*
 * dppass.exe — запускатель оболочки DPpass на Windows (D-97, T18).
 *
 * Манифест (dppass.manifest) просит права администратора: адаптер Wintun и
 * фильтры WFP без них не создать, и UAC спрашивает при каждом запуске.
 * С этими правами работает всё приложение, поэтому перед запуском JVM
 * запускатель сверяет:
 *
 *   - каждый файл и каталог комплекта (каталог dppass.exe целиком) может
 *     изменить только администратор, SYSTEM или TrustedInstaller: иначе
 *     подменённый обычным пользователем jar или DLL получил бы права
 *     администратора при следующем запуске. Не так — отказ с причиной, а не
 *     запуск;
 *   - окружение JVM чистое: переменные, которыми в JVM вставляют свой код
 *     (JAVA_TOOL_OPTIONS, _JAVA_OPTIONS, JDK_JAVA_OPTIONS, CLASSPATH),
 *     удаляются; PATH — только рантайм комплекта и системные каталоги.
 *
 * Свои аргументы запускатель не передаёт: командную строку JVM с правами
 * администратора задаёт только он. Подключение к JVM отладчиком и агентами
 * выключено (-XX:+DisableAttachMechanism). Пакет sun.nio.ch открыт, как и на
 * Linux: без него не узнать сокет канала пробы, чтобы привязать её к
 * интерфейсу мимо туннеля (D-99).
 *
 * С DPPASS_LAUNCHER_TEST собирается тестовая программа для Wine
 * (tools/desktop/windows_package.py): причины — в вывод, JVM не
 * запускается, оценка прав — и по строке SDDL. В комплект она не входит.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <wchar.h>

#ifdef DPPASS_LAUNCHER_TEST
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#endif

#define PATH_CHARS 4096
#define MESSAGE_CHARS 8192

/* Права, с которыми файл или каталог комплекта можно подменить. */
#define WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)

/* TrustedInstaller — владелец системных файлов Windows. */
#define TRUSTED_INSTALLER L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

static PSID admins;
static PSID local_system;
static PSID trusted_installer;
static PSID owner_rights;

/* Найденная проблема комплекта: путь и почему. */
static wchar_t problem[MESSAGE_CHARS];

#ifdef DPPASS_LAUNCHER_TEST
/* --walk-tree: права читаются, но не оцениваются — считается, сколько объектов обойдено. */
static BOOL walk_only;
static unsigned long walked;
#endif

static void show(const wchar_t *text)
{
#ifdef DPPASS_LAUNCHER_TEST
    fwprintf(stdout, L"refused: %ls\n", text);
#else
    MessageBoxW(NULL, text, L"DPpass", MB_OK | MB_ICONERROR);
#endif
}

static PSID well_known(WELL_KNOWN_SID_TYPE type)
{
    DWORD size = SECURITY_MAX_SID_SIZE;
    PSID sid = LocalAlloc(LMEM_FIXED, size);
    if (sid != NULL && !CreateWellKnownSid(type, NULL, sid, &size)) {
        LocalFree(sid);
        return NULL;
    }
    return sid;
}

static BOOL trusted(PSID sid)
{
    return EqualSid(sid, admins) || EqualSid(sid, local_system) || EqualSid(sid, trusted_installer);
}

/* Владелец — доверенный, и никто, кроме доверенных, не может объект изменить. */
static BOOL safe_descriptor(PSID owner, PACL dacl, const wchar_t *path)
{
    if (owner == NULL || !trusted(owner)) {
        // Владелец сам себе даёт любые права — значит, может и подменить файл.
        swprintf(problem, MESSAGE_CHARS, L"Владелец — не администраторы:\n%ls", path);
        return FALSE;
    }
    if (dacl == NULL) {
        swprintf(problem, MESSAGE_CHARS, L"Нет списка доступа — менять может любой:\n%ls", path);
        return FALSE;
    }
    for (DWORD i = 0; i < dacl->AceCount; i++) {
        ACE_HEADER *ace;
        if (!GetAce(dacl, i, (void **)&ace)) {
            swprintf(problem, MESSAGE_CHARS, L"Список доступа не прочитать:\n%ls", path);
            return FALSE;
        }
        // Наследуемое только детьми к самому объекту не относится; запрет прав не даёт.
        if ((ace->AceFlags & INHERIT_ONLY_ACE) != 0) continue;
        if (ace->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            // Условные и объектные записи на файлах не ждём: не разобрать — не запускать.
            swprintf(problem, MESSAGE_CHARS, L"Запись доступа вида %u не разобрать:\n%ls", ace->AceType, path);
            return FALSE;
        }
        ACCESS_ALLOWED_ACE *allowed = (ACCESS_ALLOWED_ACE *)ace;
        PSID sid = (PSID)&allowed->SidStart;
        // OWNER RIGHTS — права владельца, а он уже проверен.
        if ((allowed->Mask & WRITE_RIGHTS) != 0 && !trusted(sid) && !EqualSid(sid, owner_rights)) {
            wchar_t *who = NULL;
            ConvertSidToStringSidW(sid, &who);
            swprintf(problem, MESSAGE_CHARS, L"Изменять может не только администратор (%ls):\n%ls", who != NULL ? who : L"?", path);
            if (who != NULL) LocalFree(who);
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL safe_object(const wchar_t *path)
{
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD rc = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &sd);
    if (rc != ERROR_SUCCESS) {
        swprintf(problem, MESSAGE_CHARS, L"Права не прочитать (ошибка %lu):\n%ls", rc, path);
        return FALSE;
    }
#ifdef DPPASS_LAUNCHER_TEST
    walked++;
    BOOL ok = walk_only || safe_descriptor(owner, dacl, path);
#else
    BOOL ok = safe_descriptor(owner, dacl, path);
#endif
    LocalFree(sd);
    return ok;
}

/* Каталог и всё в нём, без переходов по ссылкам: ссылка внутри комплекта — сама проблема. */
static BOOL safe_tree(const wchar_t *dir)
{
    if (!safe_object(dir)) return FALSE;
    wchar_t pattern[PATH_CHARS];
    if (swprintf(pattern, PATH_CHARS, L"%ls\\*", dir) < 0) {
        swprintf(problem, MESSAGE_CHARS, L"Слишком длинный путь:\n%ls", dir);
        return FALSE;
    }
    WIN32_FIND_DATAW item;
    HANDLE find = FindFirstFileW(pattern, &item);
    if (find == INVALID_HANDLE_VALUE) {
        swprintf(problem, MESSAGE_CHARS, L"Каталог не прочитать (ошибка %lu):\n%ls", GetLastError(), dir);
        return FALSE;
    }
    BOOL ok = TRUE;
    do {
        if (wcscmp(item.cFileName, L".") == 0 || wcscmp(item.cFileName, L"..") == 0) continue;
        wchar_t path[PATH_CHARS];
        if (swprintf(path, PATH_CHARS, L"%ls\\%ls", dir, item.cFileName) < 0) {
            swprintf(problem, MESSAGE_CHARS, L"Слишком длинный путь в:\n%ls", dir);
            ok = FALSE;
        } else if ((item.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            swprintf(problem, MESSAGE_CHARS, L"Ссылка внутри комплекта — её цель не проверить:\n%ls", path);
            ok = FALSE;
        } else if ((item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            ok = safe_tree(path);
        } else {
            ok = safe_object(path);
        }
    } while (ok && FindNextFileW(find, &item));
    // Список оборвался не на конце — часть каталога не проверена: не запускать.
    if (ok && GetLastError() != ERROR_NO_MORE_FILES) {
        swprintf(problem, MESSAGE_CHARS, L"Каталог прочитан не целиком (ошибка %lu):\n%ls", GetLastError(), dir);
        ok = FALSE;
    }
    FindClose(find);
    return ok;
}

/* Окружение JVM: без переменных, вставляющих код; PATH — рантайм комплекта и системные каталоги. */
static const wchar_t *const INJECTORS[] = {L"JAVA_TOOL_OPTIONS", L"_JAVA_OPTIONS", L"JDK_JAVA_OPTIONS", L"CLASSPATH"};

static BOOL clean_environment(const wchar_t *runtime_bin)
{
    for (size_t i = 0; i < sizeof INJECTORS / sizeof INJECTORS[0]; i++) SetEnvironmentVariableW(INJECTORS[i], NULL);
    wchar_t system[PATH_CHARS], windows[PATH_CHARS], path[PATH_CHARS * 3];
    UINT s = GetSystemDirectoryW(system, PATH_CHARS);
    UINT w = GetWindowsDirectoryW(windows, PATH_CHARS);
    if (s == 0 || s >= PATH_CHARS || w == 0 || w >= PATH_CHARS) return FALSE;
    if (swprintf(path, PATH_CHARS * 3, L"%ls;%ls;%ls", runtime_bin, system, windows) < 0) return FALSE;
    return SetEnvironmentVariableW(L"PATH", path);
}

static BOOL init_sids(void)
{
    admins = well_known(WinBuiltinAdministratorsSid);
    local_system = well_known(WinLocalSystemSid);
    owner_rights = well_known(WinCreatorOwnerRightsSid);
    return admins != NULL && local_system != NULL && owner_rights != NULL && ConvertStringSidToSidW(TRUSTED_INSTALLER, &trusted_installer);
}

#ifdef DPPASS_LAUNCHER_TEST
/* Оценка прав по строке SDDL: в Wine права файлов не настоящие, а правила проверить надо. */
static int test_sddl(const wchar_t *sddl)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL)) {
        fwprintf(stdout, L"bad sddl: %ls\n", sddl);
        return 2;
    }
    PSID owner = NULL;
    PACL dacl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    GetSecurityDescriptorOwner(sd, &owner, &defaulted);
    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
    BOOL ok = safe_descriptor(owner, present ? dacl : NULL, L"(sddl)");
    if (ok) {
        fwprintf(stdout, L"safe\n");
    } else {
        fwprintf(stdout, L"refused: %ls\n", problem);
    }
    LocalFree(sd);
    return ok ? 0 : 1;
}
#endif

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR args, int show_mode)
{
    (void)instance;
    (void)previous;
    (void)show_mode;
    // Свои DLL — только из System32: запускатель с правами не грузит их из своего каталога.
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    BOOL check_tree = TRUE;
#ifdef DPPASS_LAUNCHER_TEST
    _setmode(_fileno(stdout), _O_U8TEXT);
#endif
    if (!init_sids()) {
        show(L"DPpass не смог проверить права комплекта: системные SID не построены.");
        return 1;
    }
#ifdef DPPASS_LAUNCHER_TEST
    if (wcsncmp(args, L"--sddl ", 7) == 0) return test_sddl(args + 7);
    // Права файлов в Wine не настоящие: путь после проверки — отдельным вызовом.
    if (wcscmp(args, L"--trust-tree") == 0) check_tree = FALSE;
    walk_only = wcscmp(args, L"--walk-tree") == 0;
#else
    (void)args;
#endif

    wchar_t home[PATH_CHARS];
    DWORD n = GetModuleFileNameW(NULL, home, PATH_CHARS);
    wchar_t *slash = n == 0 || n >= PATH_CHARS ? NULL : wcsrchr(home, L'\\');
    if (slash == NULL) {
        show(L"DPpass не узнал, где лежит dppass.exe.");
        return 1;
    }
    *slash = L'\0';
#ifdef DPPASS_LAUNCHER_TEST
    if (walk_only) {
        if (!safe_tree(home)) {
            fwprintf(stdout, L"refused: %ls\n", problem);
            return 1;
        }
        fwprintf(stdout, L"walked: %lu\n", walked);
        return 0;
    }
#endif
    if (check_tree && !safe_tree(home)) {
        wchar_t text[MESSAGE_CHARS * 2];
        swprintf(text, MESSAGE_CHARS * 2,
            L"DPpass не запущен: файлы комплекта может изменить не только администратор (T18).\n\n%ls\n\n"
            L"DPpass работает с правами администратора, и подменённый файл получил бы их тоже. "
            L"Распакуйте архив в каталог, куда пишут только администраторы, например C:\\Program Files\\DPpass, "
            L"и запускайте dppass.exe оттуда.",
            problem);
        show(text);
        return 1;
    }

    wchar_t runtime_bin[PATH_CHARS], javaw[PATH_CHARS], command[PATH_CHARS * 2];
    if (swprintf(runtime_bin, PATH_CHARS, L"%ls\\runtime\\bin", home) < 0
        || swprintf(javaw, PATH_CHARS, L"%ls\\javaw.exe", runtime_bin) < 0
        || swprintf(command, PATH_CHARS * 2,
               L"\"%ls\" -Dfile.encoding=UTF-8 -XX:+DisableAttachMechanism --enable-native-access=ALL-UNNAMED "
               L"--add-exports=java.base/sun.nio.ch=ALL-UNNAMED "
               L"-cp \"%ls\\lib\\*\" com.dpsmpx.dppass.desktop.MainKt",
               javaw, home) < 0) {
        show(L"Слишком длинный путь к комплекту DPpass.");
        return 1;
    }
    if (GetFileAttributesW(javaw) == INVALID_FILE_ATTRIBUTES) {
        show(L"В комплекте нет runtime\\bin\\javaw.exe — архив распакован не целиком.");
        return 1;
    }
    if (!clean_environment(runtime_bin)) {
        show(L"DPpass не смог подготовить окружение JVM.");
        return 1;
    }
#ifdef DPPASS_LAUNCHER_TEST
    // JVM не запускается: проверка — командная строка и окружение.
    wchar_t value[PATH_CHARS * 3];
    fwprintf(stdout, L"command: %ls\n", command);
    for (size_t i = 0; i < sizeof INJECTORS / sizeof INJECTORS[0]; i++) {
        if (GetEnvironmentVariableW(INJECTORS[i], value, PATH_CHARS) != 0) fwprintf(stdout, L"left: %ls\n", INJECTORS[i]);
    }
    if (GetEnvironmentVariableW(L"PATH", value, PATH_CHARS * 3) != 0) fwprintf(stdout, L"path: %ls\n", value);
    return 0;
#else
    STARTUPINFOW si = {.cb = sizeof si};
    PROCESS_INFORMATION pi;
    // Рабочий каталог — комплект: не каталог, откуда запустили и куда пишет пользователь.
    if (!CreateProcessW(javaw, command, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, home, &si, &pi)) {
        wchar_t text[MESSAGE_CHARS];
        swprintf(text, MESSAGE_CHARS, L"javaw.exe не запустился (ошибка %lu).", GetLastError());
        show(text);
        return 1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
#endif
}
