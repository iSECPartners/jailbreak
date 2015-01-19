// jailbreak.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#ifdef _M_X64
#define PROGNAME "jailbreak64"
#else
#define PROGNAME "jailbreak32"
#endif

int _tmain(int argc, _TCHAR* argv[])
{
    int ret = 0;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TCHAR* lptstr = GetCommandLine();
    TCHAR* pCommandLine = NULL;
    TCHAR* pFirstArg = NULL;
    TCHAR* pPos = NULL;
    size_t len = 0;
    BOOL bResult = FALSE;
    NTSTATUS nt = 0;
    HANDLE hLogFile = INVALID_HANDLE_VALUE;
    TCHAR tempString[2048];

    ZeroMemory(tempString, sizeof(tempString));

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(STARTUPINFO);
    ZeroMemory(&pi, sizeof(pi));

    if (argc <= 1)
    {
        printf(PROGNAME " - Launches other applications and hooks function calls\n");
        printf("            to allow for the export of non-exportable certificates.\n");
        printf("(c) 2014 iSEC Partners\n");
        printf("-------------------------------------------------------------------\n");
        printf("Usage:\n");
        printf(" " PROGNAME " <program> <options>\n\n");
        printf("Example:\n\n");
        printf(PROGNAME " c:\\windows\\system32\\mmc.exe c:\\windows\\system32\\certmgr.msc -32\n");
        printf(" - Launches the Certificate Manager and allows it to export non-exportable\n");
        printf("   certificates.\n");
        return -1;
    }

    // See if there is a log file which indicates we should log our progress.
    hLogFile = CreateFile(L"jailbreak.log", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ,
                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // Using argv[] and GetCommandLine so I can steal the correctly quoted command line from GetCommandLine
    // instead of using argv[] and concatenating a bunch of strings and getting quoting correct. Using
    // argv[] so I know where the arguments start in the string from GetCommandLine
    pFirstArg = argv[1];
    pPos = _tcsstr(lptstr, pFirstArg);
    if (pPos == NULL)
    {
        printf("Could not find first argument [%S] in command line [%S]\n", pFirstArg, lptstr);
        return -1;
    }

    // If first parameter is quoted the quote doesn't show up in argv[] but
    // it does show up in GetCommandLine.
    if (pPos[-1] == _T('\"') || pPos[-1] == _T('\''))
        pPos--;

    len = _tcslen(pPos);
    pCommandLine = (TCHAR*)calloc(len + 1, sizeof(TCHAR));
    if (!pCommandLine)
    {
        printf("Failed to allocate memory\n");
        return -1;
    }

    StringCchCopy(pCommandLine, len + 1, pPos);

    if (hLogFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        StringCchPrintf(tempString, sizeof(tempString)/sizeof(TCHAR), L"\r\n(%d): %S\r\n", GetCurrentProcessId(), PROGNAME);
        SetFilePointer(hLogFile, 0, 0, FILE_END);
        if (!WriteFile(hLogFile, tempString, (DWORD)(_tcslen(tempString)*sizeof(TCHAR)), &dwWritten, NULL))
        {
            printf("Failed to write to jailbreak.log no logging will be performed. (%d)\n", GetLastError());
            CloseHandle(hLogFile);
            hLogFile = INVALID_HANDLE_VALUE;
        }
    }

    if (hLogFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): Launching new process = %s\r\n", GetCurrentProcessId(), pCommandLine);
        WriteFile(hLogFile, tempString, (DWORD)(_tcslen(tempString)*sizeof(TCHAR)), &dwWritten, NULL);
    }

    bResult = CreateProcess(NULL,
        pCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!bResult)
    {
        printf("CreateProces failed with error code = %d\n", GetLastError());
        printf("Command line = %S\n", pCommandLine);
        return -1;
    }

    if (hLogFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): Injecting hook library to process %d\r\n", GetCurrentProcessId(), pi.dwProcessId);
        WriteFile(hLogFile, tempString, (DWORD)(_tcslen(tempString)*sizeof(TCHAR)), &dwWritten, NULL);
    }

    nt = RhInjectLibrary(pi.dwProcessId, 0, EASYHOOK_INJECT_DEFAULT,
        L"jailbreakhook32.dll",
        L"jailbreakhook64.dll", NULL, 0);

    if (nt != 0)
    {
        printf("RhInjectLibrary failed with error code = %d\n", nt);
        ret = -1;
    }
    printf("\n");

    ResumeThread(pi.hThread);

    if (pCommandLine)
        free(pCommandLine);

    WaitForSingleObject(pi.hProcess, 5000);

    if (hLogFile != INVALID_HANDLE_VALUE)
        CloseHandle(hLogFile);

    return ret;
}

