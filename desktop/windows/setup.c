/*
 * setup.exe и uninstall.exe — установщик DPpass на Windows (D-100, T18).
 *
 * setup.exe (из распакованного архива, права администратора — один раз):
 *   - копирует комплект в C:\Program Files\DPpass: писать туда могут только
 *     администраторы, этого требует проверка прав запускателя (T18);
 *   - сверяет каждый скопированный файл с SHA-256, вшитой в сам установщик
 *     (payload.h — tools/desktop/windows_package.py): файл, подменённый в
 *     «Загрузках» между распаковкой и копированием, не установится;
 *   - регистрирует задачу планировщика «DPpass» с наивысшими правами для
 *     вошедшего пользователя — ярлык запускает её, и UAC больше не
 *     спрашивает; по выбору — и при входе в Windows. Список доступа задачи:
 *     менять её могут только администраторы и SYSTEM, пользователь — только
 *     читать и запускать; иначе любая его программа подменила бы команду и
 *     получила права администратора без вопроса;
 *   - ярлык в меню «Пуск» (dppass-start.exe) и запись в «Установленных
 *     приложениях» с удалением.
 * Задача — только для администратора, вошедшего в Windows: у обычного
 * пользователя наивысшие права — обычные, и ярлык тогда запускает
 * dppass.exe, а UAC спрашивает пароль администратора, как раньше (D-97).
 *
 * uninstall.exe (в каталоге установки) убирает задачу, ярлык, запись и
 * файлы; данные пользователя (%LOCALAPPDATA%\DPpass) остаются.
 *
 * Своих DLL рядом с установщиком в «Загрузках» он не загрузит: статически —
 * только системные из KnownDLLs, остальное — только из System32.
 *
 * С DPPASS_SETUP_TEST собирается программа для Wine: каталог, раздел
 * реестра (HKCU) и имя задачи — тестовые, вопросы — аргументами, ответы —
 * в вывод. В комплект она не входит.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <objidl.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include <wtsapi32.h>

#ifdef DPPASS_SETUP_TEST
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#endif

/* Части по сборкам: установка (setup.exe и тест), удаление (uninstall.exe и тест). */
#ifndef DPPASS_UNINSTALL
#define INSTALL_PART 1
#include "payload.h"
#endif
#if defined(DPPASS_UNINSTALL) || defined(DPPASS_SETUP_TEST)
#define UNINSTALL_PART 1
#endif

#define PATH_CHARS 4096
#define MESSAGE_CHARS 8192
#define XML_CHARS 16384

#ifdef DPPASS_SETUP_TEST
#define TASK_NAME L"DPpassSetupTest"
#define UNINSTALL_ROOT HKEY_CURRENT_USER
#define UNINSTALL_KEY L"Software\\DPpassSetupTest\\Uninstall\\DPpass"
#else
#define TASK_NAME L"DPpass"
#define UNINSTALL_ROOT HKEY_LOCAL_MACHINE
#define UNINSTALL_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\DPpass"
#endif

#ifdef INSTALL_PART
static wchar_t message[MESSAGE_CHARS];
#endif

static void say(const wchar_t *text, UINT icon)
{
#ifdef DPPASS_SETUP_TEST
    (void)icon;
    fwprintf(stdout, L"say: %ls\n", text);
#else
    MessageBoxW(NULL, text, L"DPpass", MB_OK | icon);
#endif
}

#ifndef DPPASS_SETUP_TEST
static BOOL ask(const wchar_t *text)
{
    return MessageBoxW(NULL, text, L"DPpass", MB_YESNO | MB_ICONQUESTION) == IDYES;
}
#endif

static BOOL join(wchar_t *out, const wchar_t *a, const wchar_t *b)
{
    int n = swprintf(out, PATH_CHARS, L"%ls\\%ls", a, b);
    return n > 0 && n < PATH_CHARS;
}

#ifndef DPPASS_SETUP_TEST
/* Каталог исполняемого файла. */
static BOOL module_dir(wchar_t *out)
{
    DWORD n = GetModuleFileNameW(NULL, out, PATH_CHARS);
    if (n == 0 || n >= PATH_CHARS) return FALSE;
    wchar_t *slash = wcsrchr(out, L'\\');
    if (slash == NULL) return FALSE;
    *slash = 0;
    return TRUE;
}
#endif

#ifdef INSTALL_PART
/* ---- SHA-256 (FIPS 180-4) ---- */

typedef struct {
    uint32_t h[8];
    uint64_t bytes;
    uint8_t block[64];
    size_t used;
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t rotr(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
    static const uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, H0, sizeof H0);
    c->bytes = 0;
    c->used = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n)
{
    c->bytes += n;
    while (n > 0) {
        size_t take = 64 - c->used < n ? 64 - c->used : n;
        memcpy(c->block + c->used, p, take);
        c->used += take;
        p += take;
        n -= take;
        if (c->used == 64) {
            sha256_block(c, c->block);
            c->used = 0;
        }
    }
}

static void sha256_hex(sha256_ctx *c, char hex[65])
{
    uint64_t bits = c->bytes * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    pad = 0;
    while (c->used != 56) sha256_update(c, &pad, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, len, 8);
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        uint8_t byte = (uint8_t)(c->h[i / 4] >> (24 - 8 * (i % 4)));
        hex[2 * i] = digits[byte >> 4];
        hex[2 * i + 1] = digits[byte & 15];
    }
    hex[64] = 0;
}

static BOOL hash_file(const wchar_t *path, char hex[65])
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    static uint8_t buf[1 << 16];
    sha256_ctx c;
    sha256_init(&c);
    DWORD got;
    BOOL ok;
    while ((ok = ReadFile(f, buf, sizeof buf, &got, NULL)) && got > 0) sha256_update(&c, buf, got);
    CloseHandle(f);
    if (!ok) return FALSE;
    sha256_hex(&c, hex);
    return TRUE;
}
#endif

/* ---- файлы ---- */

#ifdef INSTALL_PART
/* Каталоги пути до последней «\», как CreateDirectory по одному. */
static BOOL make_parents(const wchar_t *path)
{
    wchar_t dir[PATH_CHARS];
    wcsncpy(dir, path, PATH_CHARS - 1);
    dir[PATH_CHARS - 1] = 0;
    for (wchar_t *p = dir + 3; *p; p++) {
        if (*p != L'\\') continue;
        *p = 0;
        if (!CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;
        *p = L'\\';
    }
    return TRUE;
}
#endif

/*
 * Удалить каталог dir целиком; keep — файл, который удалить нельзя (сам
 * uninstall.exe): он и то, что не удалилось, удаляются при перезагрузке.
 * Ссылки не открываются — удаляются сами. FALSE — что-то осталось до
 * перезагрузки.
 */
static BOOL remove_tree(const wchar_t *dir, const wchar_t *keep)
{
    wchar_t pattern[PATH_CHARS], child[PATH_CHARS];
    if (!join(pattern, dir, L"*")) return FALSE;
    BOOL clean = TRUE;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            if (!join(child, dir, fd.cFileName)) {
                clean = FALSE;
                continue;
            }
            BOOL is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            BOOL link = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            if (is_dir && !link) {
                if (!remove_tree(child, keep)) clean = FALSE;
                continue;
            }
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(child, FILE_ATTRIBUTE_NORMAL);
            BOOL gone = (keep != NULL && _wcsicmp(child, keep) == 0) ? FALSE : (is_dir ? RemoveDirectoryW(child) : DeleteFileW(child));
            if (!gone) {
                MoveFileExW(child, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                clean = FALSE;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (!RemoveDirectoryW(dir)) {
        MoveFileExW(dir, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        clean = FALSE;
    }
    return clean;
}

/* ---- процессы ---- */

/* Программа из System32 без окна; код выхода, (DWORD)-1 — не запустилась. */
static DWORD run_system(const wchar_t *exe, const wchar_t *args)
{
    wchar_t sys[PATH_CHARS], path[PATH_CHARS], line[PATH_CHARS * 2];
    UINT n = GetSystemDirectoryW(sys, PATH_CHARS);
    if (n == 0 || n >= PATH_CHARS || !join(path, sys, exe)) return (DWORD)-1;
    if (swprintf(line, PATH_CHARS * 2, L"\"%ls\" %ls", path, args) < 0) return (DWORD)-1;
    STARTUPINFOW si = {.cb = sizeof si};
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(path, line, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, sys, &si, &pi)) return (DWORD)-1;
    CloseHandle(pi.hThread);
    DWORD code = (DWORD)-1;
    if (WaitForSingleObject(pi.hProcess, 120000) == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return code;
}

static DWORD schtasks(const wchar_t *verb, const wchar_t *extra)
{
    wchar_t args[PATH_CHARS * 2];
    if (swprintf(args, PATH_CHARS * 2, L"%ls /TN \"%ls\"%ls", verb, TASK_NAME, extra) < 0) return (DWORD)-1;
    return run_system(L"schtasks.exe", args);
}

#ifdef INSTALL_PART
/* ---- задача планировщика ---- */

/* SID пользователя процесса строкой (освобождать LocalFree). */
static wchar_t *token_user(void)
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
    BYTE buf[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)];
    DWORD size;
    wchar_t *sid = NULL;
    if (GetTokenInformation(token, TokenUser, buf, sizeof buf, &size)) ConvertSidToStringSidW(((TOKEN_USER *)buf)->User.Sid, &sid);
    CloseHandle(token);
    return sid;
}

/* Символы, которые в XML значат разметку, — сущностями. */
static BOOL xml_escape(wchar_t *out, size_t cap, const wchar_t *in)
{
    size_t n = 0;
    for (; *in; in++) {
        const wchar_t *rep = *in == L'&' ? L"&amp;" : *in == L'<' ? L"&lt;" : *in == L'>' ? L"&gt;" : *in == L'"' ? L"&quot;" : NULL;
        size_t len = rep ? wcslen(rep) : 1;
        if (n + len + 1 > cap) return FALSE;
        if (rep) {
            wmemcpy(out + n, rep, len);
        } else {
            out[n] = *in;
        }
        n += len;
    }
    out[n] = 0;
    return TRUE;
}

/*
 * Задача: dppass.exe с наивысшими правами для пользователя sid, когда он
 * вошёл (InteractiveToken); autostart — ещё и при входе. Список доступа:
 * администраторы и SYSTEM — всё, пользователь — чтение и запуск (FRFX).
 */
static BOOL task_xml(wchar_t *out, const wchar_t *target, const wchar_t *sid, BOOL autostart)
{
    wchar_t dir[PATH_CHARS * 2], exe[PATH_CHARS], exe_xml[PATH_CHARS * 2], trigger[1024] = L"";
    if (!xml_escape(dir, PATH_CHARS * 2, target) || !join(exe, target, L"dppass.exe") || !xml_escape(exe_xml, PATH_CHARS * 2, exe)) return FALSE;
    if (autostart && swprintf(trigger, 1024, L"<LogonTrigger><Enabled>true</Enabled><UserId>%ls</UserId></LogonTrigger>", sid) < 0) return FALSE;
    int n = swprintf(out, XML_CHARS,
        L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
        L"  <RegistrationInfo><Description>DPpass без запроса UAC (D-100)</Description>"
        L"<SecurityDescriptor>D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;%ls)</SecurityDescriptor></RegistrationInfo>\r\n"
        L"  <Triggers>%ls</Triggers>\r\n"
        L"  <Principals><Principal id=\"Author\"><UserId>%ls</UserId><LogonType>InteractiveToken</LogonType>"
        L"<RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n"
        L"  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        L"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        L"<AllowStartOnDemand>true</AllowStartOnDemand><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings>\r\n"
        L"  <Actions Context=\"Author\"><Exec><Command>%ls</Command><WorkingDirectory>%ls</WorkingDirectory></Exec></Actions>\r\n"
        L"</Task>\r\n",
        sid, trigger, sid, exe_xml, dir);
    return n > 0 && n < XML_CHARS;
}

/* Задачу — из файла в каталоге установки: туда пишут только администраторы, файл не подменить. */
static BOOL register_task(const wchar_t *target, const wchar_t *sid, BOOL autostart)
{
    static wchar_t xml[XML_CHARS];
    wchar_t file[PATH_CHARS], args[PATH_CHARS * 2];
    if (!task_xml(xml, target, sid, autostart) || !join(file, target, L"task.xml")) return FALSE;
#ifdef DPPASS_SETUP_TEST
    fwprintf(stdout, L"task: %ls", xml);
#endif
    HANDLE f = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    static const BYTE bom[] = {0xFF, 0xFE};
    DWORD written;
    BOOL ok = WriteFile(f, bom, sizeof bom, &written, NULL) && WriteFile(f, xml, (DWORD)(wcslen(xml) * sizeof(wchar_t)), &written, NULL);
    CloseHandle(f);
    if (ok) {
        if (swprintf(args, PATH_CHARS * 2, L" /XML \"%ls\" /F", file) < 0) ok = FALSE;
        if (ok) ok = schtasks(L"/Create", args) == 0;
    }
    DeleteFileW(file);
    return ok;
}
#endif

#if defined(INSTALL_PART) && !defined(DPPASS_SETUP_TEST)
/*
 * Вошедший в Windows пользователь — тот же, от чьего имени установка (а не
 * администратор, чей пароль ввёл обычный пользователь): иначе задача
 * работала бы у другого. Не узнать — считается «не тот».
 */
static BOOL same_user_as_session(void)
{
    typedef BOOL(WINAPI * query_fn)(HANDLE, DWORD, WTS_INFO_CLASS, LPWSTR *, DWORD *);
    typedef void(WINAPI * free_fn)(PVOID);
    HMODULE wts = LoadLibraryExW(L"wtsapi32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (wts == NULL) return FALSE;
    query_fn query = (query_fn)(void *)GetProcAddress(wts, "WTSQuerySessionInformationW");
    free_fn release = (free_fn)(void *)GetProcAddress(wts, "WTSFreeMemory");
    BOOL same = FALSE;
    LPWSTR session_user = NULL, session_domain = NULL;
    DWORD n;
    if (query && release && query(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &session_user, &n)
        && query(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSDomainName, &session_domain, &n)) {
        HANDLE token;
        BYTE buf[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)];
        wchar_t name[256], domain[256];
        DWORD name_n = 256, domain_n = 256, size;
        SID_NAME_USE use;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            if (GetTokenInformation(token, TokenUser, buf, sizeof buf, &size)
                && LookupAccountSidW(NULL, ((TOKEN_USER *)buf)->User.Sid, name, &name_n, domain, &domain_n, &use)) {
                same = _wcsicmp(name, session_user) == 0 && _wcsicmp(domain, session_domain) == 0;
            }
            CloseHandle(token);
        }
    }
    if (release) {
        if (session_user) release(session_user);
        if (session_domain) release(session_domain);
    }
    FreeLibrary(wts);
    return same;
}
#endif

/* ---- ярлык и запись удаления ---- */

#ifdef INSTALL_PART
static BOOL shortcut(const wchar_t *lnk, const wchar_t *exe, const wchar_t *dir, const wchar_t *icon)
{
    if (!make_parents(lnk)) return FALSE;
    HRESULT init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    IShellLinkW *link = NULL;
    IPersistFile *file = NULL;
    BOOL ok = SUCCEEDED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&link))
        && SUCCEEDED(IShellLinkW_SetPath(link, exe)) && SUCCEEDED(IShellLinkW_SetWorkingDirectory(link, dir))
        && SUCCEEDED(IShellLinkW_SetIconLocation(link, icon, 0)) && SUCCEEDED(IShellLinkW_SetDescription(link, L"DPpass"))
        && SUCCEEDED(IShellLinkW_QueryInterface(link, &IID_IPersistFile, (void **)&file)) && SUCCEEDED(IPersistFile_Save(file, lnk, TRUE));
    if (file) IPersistFile_Release(file);
    if (link) IShellLinkW_Release(link);
    if (SUCCEEDED(init)) CoUninitialize();
    return ok;
}
#endif

#ifdef INSTALL_PART
static BOOL set_string(HKEY key, const wchar_t *name, const wchar_t *value)
{
    return RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value, (DWORD)((wcslen(value) + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

static BOOL set_dword(HKEY key, const wchar_t *name, DWORD value)
{
    return RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE *)&value, sizeof value) == ERROR_SUCCESS;
}
#endif

/* Где ярлык в меню «Пуск»: для всех пользователей; в тесте — рядом с каталогом установки. */
static BOOL shortcut_path(wchar_t *out, const wchar_t *target)
{
#ifdef DPPASS_SETUP_TEST
    return swprintf(out, PATH_CHARS, L"%ls.menu\\DPpass.lnk", target) > 0;
#else
    (void)target;
    PWSTR programs = NULL;
    BOOL ok = SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_CommonPrograms, 0, NULL, &programs)) && join(out, programs, L"DPpass.lnk");
    CoTaskMemFree(programs);
    return ok;
#endif
}

/* ---- установка ---- */

#ifdef INSTALL_PART

static BOOL uninstall_entry(const wchar_t *target)
{
    HKEY key;
    wchar_t uninstall[PATH_CHARS], icon[PATH_CHARS], command[PATH_CHARS + 2];
    if (!join(uninstall, target, L"uninstall.exe") || !join(icon, target, L"dppass.exe")) return FALSE;
    if (swprintf(command, PATH_CHARS + 2, L"\"%ls\"", uninstall) < 0) return FALSE;
    if (RegCreateKeyExW(UNINSTALL_ROOT, UNINSTALL_KEY, 0, NULL, 0, KEY_WRITE | KEY_WOW64_64KEY, NULL, &key, NULL) != ERROR_SUCCESS) return FALSE;
    BOOL ok = set_string(key, L"DisplayName", L"DPpass") && set_string(key, L"DisplayVersion", DPPASS_VERSION_W)
        && set_string(key, L"Publisher", L"DPpass") && set_string(key, L"InstallLocation", target)
        && set_string(key, L"UninstallString", command) && set_string(key, L"DisplayIcon", icon)
        && set_dword(key, L"NoModify", 1) && set_dword(key, L"NoRepair", 1);
    RegCloseKey(key);
    return ok;
}

/* Вернуть прежнюю установку, если новая не встала. */
static void restore(const wchar_t *target, const wchar_t *old, BOOL had_old)
{
    remove_tree(target, NULL);
    if (had_old) MoveFileExW(old, target, 0);
}

/*
 * Установить комплект из source в target: копия, сверка с вшитыми суммами,
 * задача (если sid), ярлык, запись удаления. Прежняя установка
 * переименовывается и удаляется только после того, как новая встала; не
 * переименовалась — DPpass запущен, и ничего не трогается.
 */
static BOOL install(const wchar_t *source, const wchar_t *target, const wchar_t *sid, BOOL autostart)
{
    wchar_t from[PATH_CHARS], to[PATH_CHARS], old[PATH_CHARS];
    for (size_t i = 0; i < PAYLOAD_COUNT; i++) {
        if (!join(from, source, PAYLOAD[i].path) || GetFileAttributesW(from) == INVALID_FILE_ATTRIBUTES) {
            swprintf(message, MESSAGE_CHARS, L"Архив распакован не целиком: нет %ls. Распакуйте его заново.", PAYLOAD[i].path);
            return FALSE;
        }
    }
    if (swprintf(old, PATH_CHARS, L"%ls.old", target) < 0) return FALSE;
    BOOL had_old = GetFileAttributesW(target) != INVALID_FILE_ATTRIBUTES;
    if (had_old) {
        schtasks(L"/End", L"");
        if (GetFileAttributesW(old) != INVALID_FILE_ATTRIBUTES) remove_tree(old, NULL);
        if (!MoveFileExW(target, old, 0)) {
            swprintf(message, MESSAGE_CHARS,
                L"Прежний DPpass в %ls занят (ошибка %lu): закройте DPpass и запустите установку снова.", target, GetLastError());
            return FALSE;
        }
    }
    if (!CreateDirectoryW(target, NULL)) {
        swprintf(message, MESSAGE_CHARS, L"Не создать %ls (ошибка %lu).", target, GetLastError());
        restore(target, old, had_old);
        return FALSE;
    }
    char hex[65];
    for (size_t i = 0; i < PAYLOAD_COUNT; i++) {
        join(from, source, PAYLOAD[i].path);
        join(to, target, PAYLOAD[i].path);
        if (!make_parents(to) || !CopyFileW(from, to, TRUE)) {
            swprintf(message, MESSAGE_CHARS, L"Не скопировать %ls (ошибка %lu).", PAYLOAD[i].path, GetLastError());
            restore(target, old, had_old);
            return FALSE;
        }
        // Сверка — уже в каталоге, куда пишут только администраторы: дальше файл не подменить.
        if (!hash_file(to, hex) || strcmp(hex, PAYLOAD[i].sha256) != 0) {
            swprintf(message, MESSAGE_CHARS,
                L"Файл %ls не тот, что в архиве DPpass: его изменили после распаковки. Скачайте архив заново и сверьте SHA256SUMS.",
                PAYLOAD[i].path);
            restore(target, old, had_old);
            return FALSE;
        }
    }
    if (sid != NULL && !register_task(target, sid, autostart)) {
        swprintf(message, MESSAGE_CHARS, L"Задачу планировщика «%ls» не зарегистрировать.", TASK_NAME);
        restore(target, old, had_old);
        return FALSE;
    }
    wchar_t lnk[PATH_CHARS], start[PATH_CHARS], icon[PATH_CHARS];
    if (!shortcut_path(lnk, target) || !join(start, target, L"dppass-start.exe") || !join(icon, target, L"dppass.exe")
        || !shortcut(lnk, start, target, icon) || !uninstall_entry(target)) {
        swprintf(message, MESSAGE_CHARS, L"Ярлык или запись в «Установленных приложениях» не созданы.");
        restore(target, old, had_old);
        return FALSE;
    }
    if (had_old) remove_tree(old, NULL);
    return TRUE;
}

#endif

/* ---- удаление ---- */

#ifdef UNINSTALL_PART
static BOOL uninstall(const wchar_t *target, const wchar_t *self)
{
    schtasks(L"/End", L"");
    DWORD deleted = schtasks(L"/Delete", L" /F");
    wchar_t lnk[PATH_CHARS];
    if (shortcut_path(lnk, target)) DeleteFileW(lnk);
#ifdef DPPASS_SETUP_TEST
    fwprintf(stdout, L"task deleted: %lu\n", deleted);
    wchar_t menu[PATH_CHARS];
    if (swprintf(menu, PATH_CHARS, L"%ls.menu", target) > 0) RemoveDirectoryW(menu);
#else
    (void)deleted;
#endif
    RegDeleteKeyExW(UNINSTALL_ROOT, UNINSTALL_KEY, KEY_WOW64_64KEY, 0);
    return remove_tree(target, self);
}
#endif

/* ---- точки входа ---- */

#ifdef DPPASS_SETUP_TEST

/*
 * setup-test hash FILE | install SOURCE TARGET [autostart] | uninstall TARGET.
 * Задача — тестовая и для пользователя процесса (Wine), реестр — HKCU.
 */
int wmain(int argc, wchar_t **argv)
{
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    _setmode(_fileno(stdout), _O_U8TEXT);
    if (argc == 3 && wcscmp(argv[1], L"hash") == 0) {
        char hex[65];
        if (!hash_file(argv[2], hex)) return 2;
        fwprintf(stdout, L"%hs\n", hex);
        return 0;
    }
    if ((argc == 4 || argc == 5) && wcscmp(argv[1], L"install") == 0) {
        wchar_t *sid = token_user();
        BOOL ok = sid != NULL && install(argv[2], argv[3], sid, argc == 5 && wcscmp(argv[4], L"autostart") == 0);
        LocalFree(sid);
        if (!ok) say(message, MB_ICONERROR);
        return ok ? 0 : 1;
    }
    if (argc == 3 && wcscmp(argv[1], L"uninstall") == 0) return uninstall(argv[2], NULL) ? 0 : 1;
    fwprintf(stdout, L"usage: hash FILE | install SOURCE TARGET [autostart] | uninstall TARGET\n");
    return 2;
}

#else

static BOOL program_files_target(wchar_t *out)
{
    PWSTR base = NULL;
    BOOL ok = SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, NULL, &base)) && join(out, base, L"DPpass");
    CoTaskMemFree(base);
    return ok;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR args, int show_mode)
{
    (void)instance;
    (void)previous;
    (void)args;
    (void)show_mode;
    // DLL — только из System32: рядом с установщиком в «Загрузках» может лежать чужая.
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    SetDllDirectoryW(L"");
    wchar_t here[PATH_CHARS], target[PATH_CHARS];
    if (!module_dir(here) || !program_files_target(target)) {
        say(L"Не найти каталог Program Files.", MB_ICONERROR);
        return 1;
    }
#ifdef DPPASS_UNINSTALL
    // Удаляет только установку в Program Files: копия uninstall.exe в другом месте ничего не сотрёт.
    if (_wcsicmp(here, target) != 0) {
        say(L"Эта программа удаляет DPpass из Program Files; запустите её оттуда или из «Установленных приложений».", MB_ICONERROR);
        return 1;
    }
    if (!ask(L"Удалить DPpass? Данные и настройки в %LOCALAPPDATA%\\DPpass останутся.")) return 0;
    wchar_t self[PATH_CHARS];
    if (GetModuleFileNameW(NULL, self, PATH_CHARS) == 0) return 1;
    if (uninstall(target, self)) {
        say(L"DPpass удалён.", MB_ICONINFORMATION);
    } else {
        say(L"DPpass удалён; часть файлов занята и удалится после перезагрузки.", MB_ICONINFORMATION);
    }
    return 0;
#else
    if (_wcsicmp(here, target) == 0) {
        say(L"Установщик запущен из каталога установки — запустите его из распакованного архива.", MB_ICONERROR);
        return 1;
    }
    wchar_t *sid = NULL;
    BOOL autostart = FALSE;
    if (same_user_as_session()) {
        sid = token_user();
        autostart = ask(L"Запускать DPpass при входе в Windows?");
    }
    if (!install(here, target, sid, autostart)) {
        LocalFree(sid);
        say(message, MB_ICONERROR);
        return 1;
    }
    wchar_t done[MESSAGE_CHARS];
    swprintf(done, MESSAGE_CHARS, L"DPpass установлен в %ls, ярлык — в меню «Пуск».%ls\n\nЗапустить DPpass сейчас?", target,
        sid != NULL ? L" Запуск — без запроса UAC." : L"\n\nЗадача без запроса UAC не создана: установку подтвердил другой пользователь (администратор), а у вас DPpass будет спрашивать права при каждом запуске.");
    LocalFree(sid);
    if (ask(done)) {
        wchar_t start[PATH_CHARS];
        if (join(start, target, L"dppass-start.exe")) ShellExecuteW(NULL, L"open", start, NULL, target, SW_SHOWNORMAL);
    }
    return 0;
#endif
}

#endif
