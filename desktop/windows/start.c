/*
 * dppass-start.exe — ярлык DPpass в меню «Пуск» (D-100): без прав
 * администратора запускает задачу планировщика «DPpass», а она — dppass.exe
 * с наивысшими правами, без запроса UAC. Задачи нет (её не создал
 * установщик или её удалили) — dppass.exe напрямую, и UAC спросит права,
 * как раньше (D-97).
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>

#define PATH_CHARS 4096

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR args, int show_mode)
{
    (void)instance;
    (void)previous;
    (void)args;
    (void)show_mode;
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    SetDllDirectoryW(L"");
    wchar_t home[PATH_CHARS], sys[PATH_CHARS], schtasks[PATH_CHARS], line[PATH_CHARS * 2], dppass[PATH_CHARS];
    DWORD n = GetModuleFileNameW(NULL, home, PATH_CHARS);
    wchar_t *slash = n > 0 && n < PATH_CHARS ? wcsrchr(home, L'\\') : NULL;
    UINT s = GetSystemDirectoryW(sys, PATH_CHARS);
    if (slash == NULL || s == 0 || s >= PATH_CHARS) return 1;
    *slash = 0;
    if (swprintf(schtasks, PATH_CHARS, L"%ls\\schtasks.exe", sys) < 0
        || swprintf(line, PATH_CHARS * 2, L"\"%ls\" /Run /TN \"DPpass\"", schtasks) < 0
        || swprintf(dppass, PATH_CHARS, L"%ls\\dppass.exe", home) < 0) return 1;
    STARTUPINFOW si = {.cb = sizeof si};
    PROCESS_INFORMATION pi;
    if (CreateProcessW(schtasks, line, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, sys, &si, &pi)) {
        DWORD code = 1;
        CloseHandle(pi.hThread);
        if (WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess);
        if (code == 0) return 0;
    }
    // Без задачи — как раньше: UAC спросит права у dppass.exe.
    if ((INT_PTR)ShellExecuteW(NULL, L"open", dppass, NULL, home, SW_SHOWNORMAL) <= 32) {
        MessageBoxW(NULL, L"DPpass не запустился: нет ни задачи «DPpass», ни dppass.exe рядом с ярлыком.", L"DPpass", MB_OK | MB_ICONERROR);
        return 1;
    }
    return 0;
}
