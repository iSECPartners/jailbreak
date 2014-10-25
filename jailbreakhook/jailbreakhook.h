#include "easyhook.h"

// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the JAILBREAKHOOK_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// JAILBREAKHOOK_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef JAILBREAKHOOK_EXPORTS
#define JAILBREAKHOOK_API __declspec(dllexport)
#else
#define JAILBREAKHOOK_API __declspec(dllimport)
#endif

extern "C" JAILBREAKHOOK_API void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * remoteInfo);

// Function pointer definitions
typedef BOOL(WINAPI *PFNCRYPTGETKEYPARAM)(HCRYPTKEY, DWORD, BYTE*, DWORD*, DWORD);
typedef BOOL(WINAPI *PFNCRYPTEXPORTKEY)(HCRYPTPROV, HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*);

// Key structure passed to CPExportKey
typedef struct _KEY {
    void* pUnknown;
    DWORD dwUnknow;
    DWORD dwFlags;
} KEY;

// Magic pointer mask values found in rsaenh.dll!NTLValidate
#ifdef _M_X64
#define POINTER_MASK (0xE35A172CD96214A0)
#else
#define POINTER_MASK (0xE35A172C)
#endif
