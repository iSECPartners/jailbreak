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

    HMODULE hMod = LoadLibrary(L"cryptsp.dll");

    if (hMod == 0)
    {
        printf("LoadLibrary(\"cryptsp.dll\") failed with error code = %d\n", GetLastError());
    }
    else
    {
        pfnCryptGetKeyParam = (PFNCRYPTGETKEYPARAM)GetProcAddress(hMod, "CryptGetKeyParam");
        if (pfnCryptGetKeyParam == 0)
        {
            printf("GetProcAddress(\"CryptGetKeyParam\") failed with error code = %d\n", GetLastError());
        }
    }

    // We Hook advapi32.dll as well for Windows XP support.
    hMod = LoadLibrary(L"advapi32.dll");

    if (hMod == 0)
    {
        printf("LoadLibrary(\"advapi32.dll\") failed with error code = %d\n", GetLastError());
    }
    else
    {
        pfnCryptGetKeyParamAdv = (PFNCRYPTGETKEYPARAM)GetProcAddress(hMod, "CryptGetKeyParam");
        if (pfnCryptGetKeyParamAdv == 0)
        {
            printf("GetProcAddress(\"CryptGetKeyParam\")(Advapi32.dll) failed with error code = %d\n", GetLastError());
        }
    }

    hMod = LoadLibrary(L"rsaenh.dll");
    if (hMod == 0)
    {
        printf("LoadLibrary(\"rsaenh.dll\") failed with error code = %d\n", GetLastError());
        return;
    }

    pfnCPExportKey = (PFNCRYPTEXPORTKEY)GetProcAddress(hMod, "CPExportKey");
    if (pfnCPExportKey == 0)
    {
        printf("GetProcAddress(\"CPExportKey\") failed with error code = %d\n", GetLastError());
        return;
    }

    if (pfnCryptGetKeyParam)
    {
        nt = LhInstallHook(pfnCryptGetKeyParam, HookedCryptGetKeyParam, NULL, g_pHookCGKP);
        if (nt != 0)
        {
            printf("LhInstallHook(pfnCryptGetKeyParam) failed with error code %d\n", nt);
            return;
        }
        LhSetExclusiveACL(ACLEntries, 1, g_pHookCGKP);
    }

    if (pfnCryptGetKeyParamAdv)
    {
        nt = LhInstallHook(pfnCryptGetKeyParamAdv, HookedCryptGetKeyParamAdv, NULL, g_pHookCGKPADV);
        if (nt != 0)
        {
            printf("LhInstallHook(pfnCryptGetKeyParamAdv) failed with error code %d\n", nt);
            return;
        }
        LhSetExclusiveACL(ACLEntries, 1, g_pHookCGKPADV);
    }


    nt = LhInstallHook(pfnCPExportKey, HookedCryptExportKey, NULL, g_pHookCEXK);
    if (nt != 0)
    {
        printf("LhInstallHook(pfnCPExportKey) failed with error code %d\n", nt);
        return;
    }

    LhSetExclusiveACL(ACLEntries, 1, g_pHookCEXK);
}
