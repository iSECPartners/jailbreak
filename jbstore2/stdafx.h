// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include "strsafe.h"


// TODO: reference additional headers your program requires here

#define FUNC_INVALID 0
#define FUNC_LIST 1
#define FUNC_DUMP_ALL 2
#define FUNC_DUMP_ONE 3

#define MAX_PASSWORD 32
#define MAX_FILENAME MAX_PATH
#define MAX_SUBJECTNAME 256

#define DEFAULT_PASSWORD L"password"
#define DEFAULT_FILENAME L"out.pfx"

typedef struct _ARG_STRUCT {
    DWORD dwFunction;
    BOOL bUseSystemStore;
    WCHAR wcPassword[MAX_PASSWORD];
    TCHAR cFileName[MAX_FILENAME];
    WCHAR wcSubjectName[MAX_SUBJECTNAME];
} *PARG_STRUCT, ARG_STRUCT;

typedef void (*MYRUNFN)(VOID);

BOOL ParseArgs(unsigned int argc, TCHAR* argv[],PARG_STRUCT pArgStruct);
void ListCertificates(HCERTSTORE hStore);
void PrintCertInfo(PCCERT_CONTEXT pCertContext);
BOOL DumpAllCertificates(HCERTSTORE hStore,PARG_STRUCT pArgStruct);
BOOL DumpOneCertificate(HCERTSTORE hStore,PARG_STRUCT pArgStruct);
void usage(void);