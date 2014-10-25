// jbstore2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
    ARG_STRUCT ArgStruct;
    HCERTSTORE hStore = NULL;
    HINSTANCE hJBDll = NULL;
    MYRUNFN fnRun = NULL;

    if(!ParseArgs(argc,argv,&ArgStruct)) {
        usage();
        return 1;
    }

    //open store
    if(ArgStruct.bUseSystemStore) hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,L"MY");
    else hStore = CertOpenSystemStore(NULL, L"MY");
    if(!hStore) {
        printf("Error opening cert store: %d\n",GetLastError());
        return 1;
    }

    if(ArgStruct.dwFunction == FUNC_LIST) {
        printf("Listing certificates in %s store\n\n", (ArgStruct.bUseSystemStore)? "SYSTEM" : "USER");
        ListCertificates(hStore);
    }
    else {
        if(ArgStruct.dwFunction == FUNC_DUMP_ALL) {
            DumpAllCertificates(hStore,&ArgStruct);
        }
        else 
        {
            DumpOneCertificate(hStore,&ArgStruct);
        }
    }

    if(hStore) CertCloseStore(hStore, 0);

    return 0;
}

BOOL ParseArgs(unsigned int argc, TCHAR* argv[],PARG_STRUCT pArgStruct)
{
    DWORD i;
    if(argc <= 1) return FALSE;

    //set defaults!
    pArgStruct->dwFunction = FUNC_INVALID;
    pArgStruct->bUseSystemStore = FALSE;
    StringCchCopy(pArgStruct->wcPassword, MAX_PASSWORD, DEFAULT_PASSWORD);
    StringCchCopy(pArgStruct->cFileName, MAX_FILENAME, DEFAULT_FILENAME);
    StringCchCopy(pArgStruct->wcSubjectName, MAX_SUBJECTNAME, L"");

    for(i = 1;i < argc; i++) {
        //List certs?
        if (_tcsicmp(argv[i], L"-l") == 0) {
            if(pArgStruct->dwFunction != FUNC_INVALID) return FALSE;
            pArgStruct->dwFunction = FUNC_LIST;
        }
        //Dump all?
        else if (_tcsicmp(argv[i], L"-a") == 0) {
            if(pArgStruct->dwFunction != FUNC_INVALID) return FALSE;
            pArgStruct->dwFunction = FUNC_DUMP_ALL;
        }
        //Dump one?
        else if (_tcsicmp(argv[i], L"-1") == 0) {
            if(pArgStruct->dwFunction != FUNC_INVALID) return FALSE;
            pArgStruct->dwFunction = FUNC_DUMP_ONE;
        }
        //cert store
        else if (_tcsicmp(argv[i], L"-s") == 0) {
            if(i + 1 >= argc) return FALSE;
            else {
                if (_tcsicmp(L"SYSTEM", argv[i + 1]) == 0) pArgStruct->bUseSystemStore = TRUE;
                else if (_tcsicmp(L"USER", argv[i + 1]) == 0) pArgStruct->bUseSystemStore = FALSE;
                else return FALSE;
                i++;
            }
        }
        //password
        else if (_tcsicmp(argv[i], L"-p") == 0) {
            if(i + 1 >= argc) return FALSE;
            else {
                StringCchCopy(pArgStruct->wcPassword, MAX_PASSWORD, argv[i + 1]);
                i++;
            }
        }
        //output filename
        else if (_tcsicmp(argv[i], L"-o") == 0) {
            if(i + 1 >= argc) return FALSE;
            else {
                StringCchCopy(pArgStruct->cFileName, MAX_FILENAME, argv[i + 1]);
                i++;
            }
        }
        //subject name
        else if (_tcsicmp(argv[i], L"-n") == 0) {
            if(i + 1 >= argc) return FALSE;
            else {
                StringCchCopy(pArgStruct->wcSubjectName, MAX_SUBJECTNAME, argv[i + 1]);
                i++;
            }
        }
        else return FALSE;
    }

    return TRUE;
}

void ListCertificates(HCERTSTORE hStore)
{
    PCCERT_CONTEXT pCertContext;

    pCertContext = CertEnumCertificatesInStore(hStore,NULL);

    while(pCertContext) {
        if(pCertContext) PrintCertInfo(pCertContext);
        pCertContext = CertEnumCertificatesInStore(hStore,pCertContext);
    }
}

void PrintCertInfo(PCCERT_CONTEXT pCertContext)
{
    DWORD dwData,n;
    TCHAR *pName = NULL;

    // Get Subject name size.
    if(!(dwData = CertGetNameString(pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,NULL,0))) {
        printf("CertGetNameString error: %d\n",GetLastError());
        goto cleanup;
    }

    // Allocate memory for subject name.
    pName = (TCHAR*)calloc(sizeof(TCHAR), dwData);
        
    if(!pName) {
        printf("Unable to allocate memory for subject name: %d\n",GetLastError());
        goto cleanup;
    }

    // Get subject name.
    if(!(CertGetNameString(pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,pName,dwData))) {
        printf("CertGetNameString error: %d\n",GetLastError());
        goto cleanup;
    }

    // Print Subject Name.
    printf("Subject Name: %S\n",pName);

    printf("Serial Number: ");
    dwData = pCertContext->pCertInfo->SerialNumber.cbData;
    for (n = 0; n < dwData; n++) {
        printf("%02X ",pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
    }
    printf("\n\n");

cleanup:
    if(pName)
        free(pName);
}

BOOL DumpAllCertificates(HCERTSTORE hStore,PARG_STRUCT pArgStruct)
{
    BOOL bResult = FALSE;
    CRYPT_DATA_BLOB Blob = {};
    HANDLE hFile = NULL;
    DWORD dwBytesWritten = 0;

    if (!PFXExportCertStoreEx(hStore,&Blob,pArgStruct->wcPassword,NULL,EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)) {
        printf("Error sizing blob: %d\n", GetLastError());
        if(GetLastError() == NTE_BAD_KEY_STATE) {
            printf("This is because jbstore2 is not working, Are you using jailbreak32/64 to launch it?\n");
            printf("If there are still problems please contact iSEC Partners.\n");
        }
        return FALSE;
    }

    Blob.pbData = (PBYTE)HeapAlloc(GetProcessHeap(),0,Blob.cbData);
    if(!Blob.pbData)
    {
        printf("Error allocating data blob: %d\n", GetLastError());
        goto cleanup;
    }

    if(!PFXExportCertStoreEx(hStore,&Blob,pArgStruct->wcPassword,NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)) {
        printf("Error exporting certificates: %d\n",GetLastError());
        goto cleanup;
    }

    hFile = CreateFile(pArgStruct->cFileName,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,0);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("Error creating output file: %d\n", GetLastError());
        goto cleanup;
    }

    if(!WriteFile(hFile,Blob.pbData,Blob.cbData,&dwBytesWritten,0)) {
        printf("Error writing to file: %d\n", GetLastError());
        goto cleanup;
    }

    if (dwBytesWritten != Blob.cbData) {
        printf("Number of bytes written does not match requested!\n");
        goto cleanup;
    }

    printf("Done... Output file written to %S\n", pArgStruct->cFileName);
    bResult = TRUE;

cleanup:
    if(hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if(Blob.pbData) HeapFree(GetProcessHeap(),0,Blob.pbData);
    return bResult;
}

BOOL DumpOneCertificate(HCERTSTORE hStore,PARG_STRUCT pArgStruct)
{
    BOOL bResult = FALSE;
    PCCERT_CONTEXT pCertContext = NULL;
    HCERTSTORE hMemStore = NULL;

    pCertContext = CertFindCertificateInStore(hStore,X509_ASN_ENCODING,0,CERT_FIND_SUBJECT_STR,pArgStruct->wcSubjectName,NULL);
    if(!pCertContext) {
        return FALSE;
    }

    printf("Found the following certificate:\n");
    PrintCertInfo(pCertContext);

    hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,0,NULL,CERT_STORE_CREATE_NEW_FLAG,NULL);
    if(!hMemStore) {
        printf("Error creating memory certificate store: %d\n",GetLastError());
        goto cleanup;
    }

    if(!CertAddCertificateContextToStore(hMemStore,pCertContext,CERT_STORE_ADD_ALWAYS,NULL)) {
        printf("Error adding certificate to memory certificate store: %d\n",GetLastError());
        goto cleanup;
    }

    bResult = DumpAllCertificates(hMemStore,pArgStruct);

cleanup:
    if(hMemStore) CertCloseStore(hMemStore, 0);
    if(pCertContext) CertFreeCertificateContext(pCertContext);

    return bResult;
}

void usage(void)
{
    printf("JBStore2 - Command line export for MY System or User Store\n");
    printf("(c) 2014 iSEC Partners\n");
    printf("-------------------------------------------------------------------\n");
    printf("Usage:\n");
    printf(" jbstore2 <action> <options>\n");
    printf("Actions:\n");
    printf(" -l                 List all certificates\n");
    printf(" -a                 Dump all certificates\n");
    printf(" -1                 Dump one certificate\n");
    printf("Options:\n");
    printf(" -s <store>         Cerificate store, \"SYSTEM\" or \"USER\" (default is \"USER\")\n");
    printf(" -p <password>      Password (default is \"password\"\n");
    printf(" -o <file name>     Output file (default is \"out.pfx\"\n");
    printf(" -n <subject name>  Subject name to use when dumping one cerificate\n");
    printf("Example:\n");
    printf(" jbstore2 -l -s \"USER\"\n");
    printf(" jbstore2 -a -o foo.pfx -p foo\n");
    printf(" jbstore2 -1 -n \"iSEC User\"\n");
}