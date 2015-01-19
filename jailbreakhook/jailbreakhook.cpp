// jailbreakhook.cpp : Defines the exported functions for the DLL application.
//
#include "stdafx.h"

// Global Hook structures
HOOK_TRACE_INFO* g_pHookCGKP = NULL;
HOOK_TRACE_INFO* g_pHookCGKPADV = NULL;
HOOK_TRACE_INFO* g_pHookCEXK = NULL;

// Global function pointers to hold real implementations
PFNCRYPTGETKEYPARAM pfnCryptGetKeyParam = NULL;
PFNCRYPTGETKEYPARAM pfnCryptGetKeyParamAdv = NULL;
PFNCRYPTEXPORTKEY pfnCPExportKey = NULL;

HANDLE hLogFile = INVALID_HANDLE_VALUE;
TCHAR tempString[2048];

void WriteToLogFile(void* lpBuffer, size_t cbBytes)
{
    if (hLogFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        WriteFile(hLogFile, lpBuffer, (DWORD)cbBytes, &dwWritten, NULL);
    }
}

// This enables the UI
BOOL WINAPI HookedCryptGetKeyParam(
    _In_     HCRYPTKEY hKey,
    _In_     DWORD dwParam,
    _Out_    BYTE *pbData,
    _Inout_  DWORD *pdwDataLen,
    _In_     DWORD dwFlags
    )
{
    BOOL b = FALSE;

    StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): CryptGetKeyParam called\r\n", GetCurrentProcessId());
    WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));

    b = (*pfnCryptGetKeyParam)(hKey, dwParam, pbData, pdwDataLen, dwFlags);
    if (dwParam == KP_PERMISSIONS)
    {
        (*pbData) |= CRYPT_EXPORT;
    }
    return b;
}

BOOL WINAPI HookedCryptGetKeyParamAdv(
    _In_     HCRYPTKEY hKey,
    _In_     DWORD dwParam,
    _Out_    BYTE *pbData,
    _Inout_  DWORD *pdwDataLen,
    _In_     DWORD dwFlags
    )
{
    BOOL b = FALSE;

    StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): CryptGetKeyParamAdv called\r\n", GetCurrentProcessId());
    WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));

    b = (*pfnCryptGetKeyParamAdv)(hKey, dwParam, pbData, pdwDataLen, dwFlags);
    if (dwParam == KP_PERMISSIONS)
    {
        (*pbData) |= CRYPT_EXPORT;
    }
    return b;
}

BOOL WINAPI HookedCryptExportKey(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey,
    HCRYPTKEY hPubKey,
    DWORD dwBlobType,
    DWORD dwFlags,
    BYTE* pbData,
    DWORD* pdwbDataLen
    )
{
    KEY** ppKey = NULL;
    DWORD org = 0;
    BOOL b = FALSE;

    StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): CryptExportKey called\r\n", GetCurrentProcessId());
    WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));

    ppKey = (KEY**)(hKey ^ POINTER_MASK);
    org = (*ppKey)->dwFlags;
    (*ppKey)->dwFlags = 0x4001;
    b = (*pfnCPExportKey)(hProv, hKey, hPubKey, dwBlobType, dwFlags, pbData, pdwbDataLen);
    (*ppKey)->dwFlags = org;
    return b;

}

JAILBREAKHOOK_API void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * remoteInfo)
{
    g_pHookCGKP = new HOOK_TRACE_INFO();
    g_pHookCGKPADV = new HOOK_TRACE_INFO();
    g_pHookCEXK = new HOOK_TRACE_INFO();
    ULONG ACLEntries[1] = { (ULONG)-1 };
    NTSTATUS nt = 0;
    HMODULE hModCryptSp = NULL;
    HMODULE hModAdv = NULL;
    HMODULE hModRsa = NULL;

    ZeroMemory(tempString, sizeof(tempString));

    // See if there is a log file which indicates we should log our progress.
    hLogFile = CreateFile(L"jailbreak.log", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hLogFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): jailbreakhook.dll\r\n", GetCurrentProcessId());
        SetFilePointer(hLogFile, 0, 0, FILE_END);
        if (!WriteFile(hLogFile, tempString, (DWORD)(_tcslen(tempString)*sizeof(TCHAR)), &dwWritten, NULL))
        {
            // If we can't write our first line then don't bother trying to log later.
            CloseHandle(hLogFile);
            hLogFile = INVALID_HANDLE_VALUE;
        }
    }

    hModCryptSp = LoadLibrary(L"cryptsp.dll");

    if (hModCryptSp == 0)
    {
        StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): LoadLibrary(\"cryptsp.dll\") failed with error code = %d\r\n", GetCurrentProcessId(), GetLastError());
        WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
    }
    else
    {
        pfnCryptGetKeyParam = (PFNCRYPTGETKEYPARAM)GetProcAddress(hModCryptSp, "CryptGetKeyParam");
        if (pfnCryptGetKeyParam == 0)
        {
            StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): GetProcAddress(\"CryptGetKeyParam\") from module %X failed with error code = %d\r\n", GetCurrentProcessId(), hModCryptSp, GetLastError());
            WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
        }
    }

    // We Hook advapi32.dll as well for Windows XP support.
    hModAdv = LoadLibrary(L"advapi32.dll");

    if (hModAdv == 0)
    {
        StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): LoadLibrary(\"advapi32.dll\") failed with error code = %d\r\n", GetCurrentProcessId(), GetLastError());
        WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
    }
    else
    {
        pfnCryptGetKeyParamAdv = (PFNCRYPTGETKEYPARAM)GetProcAddress(hModAdv, "CryptGetKeyParam");
        if (pfnCryptGetKeyParamAdv == 0)
        {
            StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): GetProcAddress(\"CryptGetKeyParam\")(Advapi32.dll) from module %X failed with error code = %d\r\n", GetCurrentProcessId(), hModAdv, GetLastError());
            WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
        }
    }

    hModRsa = LoadLibrary(L"rsaenh.dll");
    if (hModRsa == 0)
    {
        StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): LoadLibrary(\"rsaenh.dll\") failed with error code = %d\r\n", GetCurrentProcessId(), GetLastError());
        WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
        return;
    }

    pfnCPExportKey = (PFNCRYPTEXPORTKEY)GetProcAddress(hModRsa, "CPExportKey");
    if (pfnCPExportKey == 0)
    {
        StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): GetProcAddress(\"CPExportKey\") from module %X failed with error code = %d\r\n", GetCurrentProcessId(), hModRsa, GetLastError());
        WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
        return;
    }

    if (pfnCryptGetKeyParam)
    {
        nt = LhInstallHook(pfnCryptGetKeyParam, HookedCryptGetKeyParam, NULL, g_pHookCGKP);
        if (nt != 0)
        {
            StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): LhInstallHook(pfnCryptGetKeyParam) failed with error code %d\r\n", GetCurrentProcessId(), nt);
            WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
            return;
        }
        else
        {
            StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): LhInstallHook(pfnCryptGetKeyParam) succedded for module %X\r\n", GetCurrentProcessId(), hModCryptSp);
            WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
        }
        LhSetExclusiveACL(ACLEntries, 1, g_pHookCGKP);
    }

    if (pfnCryptGetKeyParamAdv)
    {
        nt = LhInstallHook(pfnCryptGetKeyParamAdv, HookedCryptGetKeyParamAdv, NULL, g_pHookCGKPADV);
        if (nt != 0)
        {
            StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): LhInstallHook(pfnCryptGetKeyParamAdv) failed with error code %d\r\n", GetCurrentProcessId(), nt);
            WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
            return;
        }
        else
        {
            StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): LhInstallHook(pfnCryptGetKeyParamAdv) succedded for module %X\r\n", GetCurrentProcessId(), hModAdv);
            WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
        }
        LhSetExclusiveACL(ACLEntries, 1, g_pHookCGKPADV);
    }

    nt = LhInstallHook(pfnCPExportKey, HookedCryptExportKey, NULL, g_pHookCEXK);
    if (nt != 0)
    {
        StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): LhInstallHook(pfnCPExportKey) failed with error code %d\r\n", GetCurrentProcessId(), nt);
        WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
        return;
    }
    else
    {
        StringCchPrintf(tempString, sizeof(tempString) / sizeof(TCHAR), L"(%d): LhInstallHook(pfnCPExportKey) succedded for module %X\r\n", GetCurrentProcessId(), hModRsa);
        WriteToLogFile(tempString, _tcslen(tempString)*sizeof(TCHAR));
    }

    LhSetExclusiveACL(ACLEntries, 1, g_pHookCEXK);
}
