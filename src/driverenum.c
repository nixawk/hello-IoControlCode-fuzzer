/***********************************************************
* Project     : CrashMeat
* Author      : Nixawk
* Description : A Fuzz Framework for Analysis
* License     : GPL3
***********************************************************/

#include <windows.h>
#include <stdio.h>
#include <winioctl.h>

#include "winerr.h"
#include "driver.h"
// #include "log.h"

/***********************************************************
* OpenDriverBySymbolicLinkName
*
* Purpose: Open a driver based on symbolic link name, and
*           return a handle.
*
* Parameters:
*          LPCSTR SymbolicLinkName
*
*
* Return Values:
*          A WINDOWS HANDLE
* 
***********************************************************/
HANDLE OpenDriverBySymbolicLinkName(LPCSTR SymbolicLinkName)
{
    HANDLE hDevice = NULL;
    char SymbolicLinkPath[MAX_PATH] = {0};

    if (!SymbolicLinkName)
    {
        // printf(
        //     "{"
        //         "'func': 'OpenDriverBySymbolicLinkName', "
        //         "'error': 'The symbolic link is invalid.',"
        //         "'code': 1111"  // 1111 - error code
        //     "}\n");
        goto CLEANUP_AND_EXIT;
    }

    sprintf(SymbolicLinkPath, "\\\\.\\%s", SymbolicLinkName);
    // printf("SymbolicLinkPath: %s\n", SymbolicLinkPath);

    hDevice = CreateFile(
        SymbolicLinkPath,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (INVALID_HANDLE_VALUE == hDevice)
    {
        // printf(
        //     "{"
        //         "'func': 'OpenDriverBySymbolicLinkName', "
        //         "'error': 'The handle is invalid.',"
        //         "'code': %ld, "
        //         "'symlink': '%s'"
        //     "}\n", GetLastError(), SymbolicLinkName);
        // printf("[-] OpenDriverBySymbolicLinkName Error: [%s, %ld]\n", SymbolicLinkPath, GetLastError());
        goto CLEANUP_AND_EXIT;
    }


CLEANUP_AND_EXIT:
    return hDevice;
}

BOOL AccessDriverBySymbolicLinkName(LPCSTR SymbolicLinkName)
{
    HANDLE hDevice = OpenDriverBySymbolicLinkName(SymbolicLinkName);
    if (INVALID_HANDLE_VALUE == hDevice)
    {
        return FALSE;
    }

    CloseHandle(hDevice);
    return TRUE;
}


PDIRECTORY_BASIC_INFORMATION GetAllDriversSymbolicLink()
{

    // ---- variable part ----

    HMODULE                       hModule                 = NULL;

    // RTLINITUNICODESTRING        RtlInitUnicodeString;
    ZWOPENDIRECTORYOBJECT         ZwOpenDirectoryObject  = NULL;
    ZWQUERYDIRECTORYOBJECT        ZwQueryDirectoryObject = NULL;
    ZWCLOSE                       ZwClose = NULL;

    UNICODE_STRING                ObjectName             = RTL_CONSTANT_STRING(L"\\Global??");
    OBJECT_ATTRIBUTES             InitializedAttributes;
    ULONG                         Attributes = OBJ_CASE_INSENSITIVE;
    HANDLE                        RootDirectory          = NULL;
    PSECURITY_DESCRIPTOR          SecurityDescriptor     = NULL;

    HANDLE                        DirectoryHandle        = NULL;
    NTSTATUS                      NTStatus;

    PDIRECTORY_BASIC_INFORMATION  pSymbolicLinkDirectory = NULL;

    ULONG                         uContext;
    ULONG                         uReturnLength;

    size_t                        MallocSize             = 0x200;

    // ---- function part ----

    hModule = LoadLibrary("ntdll.dll");
    if (NULL == hModule)
    {
        printf("[-] LoadLibrary Error  : %ld\n", GetLastError());
        goto CLEANUP_AND_EXIT;
    }
    // printf("[*] LoadLibrary Success: ntdll.dll\n");

    // RtlInitUnicodeString   = (RTLINITUNICODESTRING)GetProcAddress(hModule, "RtlInitUnicodeString");
    ZwOpenDirectoryObject  = (ZWOPENDIRECTORYOBJECT)GetProcAddress(hModule, "ZwOpenDirectoryObject");
    ZwQueryDirectoryObject = (ZWQUERYDIRECTORYOBJECT)GetProcAddress(hModule, "ZwQueryDirectoryObject");
    ZwClose                = (ZWCLOSE)GetProcAddress(hModule, "ZwClose");

    // printf("[*] GetProcAddress Success: RtlInitUnicodeString\n");
    // printf("[*] GetProcAddress Success: ZwOpenDirectoryObject\n");
    // printf("[*] GetProcAddress Success: ZwQueryDirectoryObject\n");
    // printf("[*] GetProcAddress Success: ZwClose\n");

    if (!ZwOpenDirectoryObject || !ZwQueryDirectoryObject || !ZwClose)
    {
        printf("[-] GetProcAddress Error : %ld\n", GetLastError());
        goto CLEANUP_AND_EXIT;
    }

    InitializeObjectAttributes(
        &InitializedAttributes,
        &ObjectName,
        Attributes,
        RootDirectory,
        SecurityDescriptor
    );
    // printf("[*] InitializeObjectAttributes Success\n");

    NTStatus = ZwOpenDirectoryObject(
        &DirectoryHandle,
        DIRECTORY_QUERY,
        &InitializedAttributes
    );
    if (STATUS_SUCCESS != NTStatus)
    {
        printf("[-] ZwOpenDirectoryObject Error : %ld\n", GetLastError());
        goto CLEANUP_AND_EXIT;
    }
    // printf("[*] ZwOpenDirectoryObject Success\n");

    do
    {
        if (NULL != pSymbolicLinkDirectory)
        {
            free(pSymbolicLinkDirectory);
        }

        MallocSize *= 2;
        pSymbolicLinkDirectory = (PDIRECTORY_BASIC_INFORMATION)malloc(MallocSize);
        if (NULL == pSymbolicLinkDirectory)
        {
            printf("[-] malloc Error: %ld\n", GetLastError());
            goto CLEANUP_AND_EXIT;
        }

        NTStatus = ZwQueryDirectoryObject(
            DirectoryHandle,
            pSymbolicLinkDirectory,
            MallocSize,
            FALSE,
            TRUE,
            &uContext,
            &uReturnLength
        );

        // printf("[!] ZwQueryDirectoryObject out return is %ld.\n", uReturnLength);
    } while (STATUS_MORE_ENTRIES == NTStatus || STATUS_BUFFER_TOO_SMALL == NTStatus);


CLEANUP_AND_EXIT:

    if (NULL != DirectoryHandle)
    {
        ZwClose(DirectoryHandle);
    }

    if (NULL != hModule)
    {
        FreeLibrary(hModule);
    }

    return pSymbolicLinkDirectory;
}

void PrintAllDriverSymbolicLink()
{
    char                         SymbolicLinkPath[MAX_PATH] = {0};
    int                          AvailableSymbolicLinkNameCount = 0;
    int                          UnAvailableSymbolicLinkNameCount = 0;
    PDIRECTORY_BASIC_INFORMATION pSymbolicLinkDirectory = NULL;
    BOOL                         AccessStatus = FALSE;

    pSymbolicLinkDirectory = GetAllDriversSymbolicLink();
    if (NULL == pSymbolicLinkDirectory)
    {
        printf("[-] PrintAllDriverSymbolicLink Error: No available SymbolicLinkName\n");
        exit(-1);
    }

    while ((pSymbolicLinkDirectory->ObjectName.Length != 0) && (pSymbolicLinkDirectory->ObjectTypeName.Length != 0))
    {
        // wctomb(SymbolicLinkPath, pBufferBackup->ObjectName.Buffer);  // PWSTR -> LPCSTR
        WideCharToMultiByte(
            CP_ACP,
            0,
            pSymbolicLinkDirectory->ObjectName.Buffer,
            -1,
            SymbolicLinkPath,
            sizeof(SymbolicLinkPath),
            NULL,
            NULL
        );

        AccessStatus = AccessDriverBySymbolicLinkName(SymbolicLinkPath);

        printf(
            "{'ObjectName': '%S', "
            "'ObjectTypeName': '%S', "
            "'AccessStatus': '%s', "
            "'GetLastError': %ld}\n",
            pSymbolicLinkDirectory->ObjectName.Buffer,
            pSymbolicLinkDirectory->ObjectTypeName.Buffer,
            AccessStatus ? "Yes" : "No",
            GetLastError()
        );

        if (AccessStatus)
            AvailableSymbolicLinkNameCount++;
        else
            UnAvailableSymbolicLinkNameCount++;

        pSymbolicLinkDirectory++;
    }

    printf(
        "\n[*] All SymbolicLink - Available : %d, SymbolicLinkName: %d\n",
        AvailableSymbolicLinkNameCount,
        UnAvailableSymbolicLinkNameCount
    );
}

// References
// https://msdn.microsoft.com/en-us/library/6ewkz86d.aspx
// http://www.moserware.com/2008/01/constants-on-left-are-better-but-this.html
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
