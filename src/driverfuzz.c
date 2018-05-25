/***********************************************************
* Project     : CrashMeat
* Author      : Nixawk
* Description : A Fuzz Framework for Analysis
* License     : GPL3
***********************************************************/

#include <windows.h>

#include "winerr.h"
#include "driver.h"
// #include "log.h"


BOOL Fuzz_Stack_Overflow(LPCSTR SymbolicLinkName, DWORD dwIoControlCode, char paddingChar)
{
    BOOL bStatus = FALSE;
    DWORD BytesReturned = 0;
    HANDLE hDevice = NULL;
    char InBuffer[MAX_STACKOVERFLOW_SIZE] = {0};

    hDevice = OpenDriverBySymbolicLinkName(SymbolicLinkName);
    if (NULL == hDevice)
    {
        exit(GetLastError());
    }

    printf(
        "{"
            "'func': 'Fuzz_Stack_Overflow', "
            "'text': 'IoControlCode: %08X',"
            "'code': %ld,"
            "'symlink': '%s',"
            "'bufsize': %ld,"
        "}\n",
        dwIoControlCode, GetLastError(), SymbolicLinkName, MAX_STACKOVERFLOW_SIZE
    );

    memset(InBuffer, paddingChar, MAX_STACKOVERFLOW_SIZE);

    bStatus = DeviceIoControl(
        hDevice,
        dwIoControlCode,
        (LPVOID)InBuffer,
        MAX_STACKOVERFLOW_SIZE,
        NULL,
        0,
        &BytesReturned,
        NULL
    );

    // ERROR_INVALID_FUNCTION - 1
    // ERROR_GEN_FAILURE      - 31 (0x1F)

    CloseHandle(hDevice);

    return bStatus;
}

BOOL Fuzz_NULL_Pointer(LPCSTR SymbolicLinkName, DWORD dwIoControlCode)
{
	BOOL bStatus = FALSE;
	DWORD BytesReturned = 0;
	HANDLE hDevice = NULL;

	hDevice = OpenDriverBySymbolicLinkName(SymbolicLinkName);
	if (NULL == hDevice)
	{
		exit(GetLastError());
	}

    printf(
        "{"
            "'func': 'Fuzz_NULL_Pointer', "
            "'text': 'IoControlCode: %08X',"
            "'code': %ld,"
            "'symlink': '%s'"
        "}\n",
        dwIoControlCode, GetLastError(), SymbolicLinkName
    );

    bStatus = DeviceIoControl(
    	hDevice,
    	dwIoControlCode,
    	NULL,
    	0,
    	NULL,
    	0,
    	&BytesReturned,
    	NULL
    );

    // ERROR_INVALID_FUNCTION - 1
    // ERROR_GEN_FAILURE      - 31 (0x1F)

    CloseHandle(hDevice);

    return bStatus;
}


BOOL Fuzz_Invalid_Address(LPCSTR SymbolicLinkName, DWORD dwIoControlCode)
{
    BOOL bStatus = FALSE;
    DWORD BytesReturned = 0;
    HANDLE hDevice = NULL;

    LPVOID InvalidHeapAddress = NULL;

    int   i;

#ifdef _WIN64
    DWORD InvalidAddress[] = {
        0x0000000000000000,
        0x00000000FFFFFFFF,
        0xFFFFFFFF00000000,
        0x8000000000000000,
        0xCCCCCCCCCCCCCCCC,
        0xFFFFFFFFFFFFFFFF,
    };
#else
    DWORD InvalidAddress[] = {
        0x00000000,
        0x0000FFFF,
        0x80000000,
        0xCCCCCCCC,
        0xFFFF0000,
        0xFFFFFFFF,
    };
#endif

    hDevice = OpenDriverBySymbolicLinkName(SymbolicLinkName);
    if (NULL == hDevice)
    {
        exit(GetLastError());
    }

    for (i = 0; i < (sizeof(InvalidAddress) / sizeof(InvalidAddress[0])); i++)
    {

        printf(
            "{"
                "'func': 'Fuzz_Invalid_Address', "
                "'text': 'IoControlCode: %08X, InvalidAddress: %08X',"
                "'symlink': '%s',"
                "'bufsize': %ld"
            "}\n",
            dwIoControlCode, InvalidAddress[i], SymbolicLinkName, MAX_STACKOVERFLOW_SIZE
        );

        bStatus = DeviceIoControl(
            hDevice,
            dwIoControlCode,
            (LPVOID)InvalidAddress[i],
            MAX_STACKOVERFLOW_SIZE,      // Length ?
            (LPVOID)InvalidAddress[i],
            MAX_STACKOVERFLOW_SIZE,
            &BytesReturned,
            NULL
        );

    }

    InvalidHeapAddress = malloc(MAX_STACKOVERFLOW_SIZE);
    if (NULL == InvalidHeapAddress)
    {
        printf(
            "{"
                "'func': 'Fuzz_Invalid_Address', "
                "'error': 'Failed to malloc heap memory.',"
                "'code': %ld"  // 1111 - error code
            "}\n", GetLastError());
    }
    free(InvalidHeapAddress);  // Release and Use By DeviceIoControl


    for (i = MAX_HEAPADDRESS_COUNT; i > 0; i--)
    {
        printf(
            "{"
                "'func': 'Fuzz_Invalid_Address', "
                "'text': 'IoControlCode: %08X, InvalidHeapAddress: %08X',"
                "'symlink': '%s',"
                "'bufsize': %ld"
            "}\n",
            dwIoControlCode, (DWORD)InvalidHeapAddress + i, SymbolicLinkName, MAX_STACKOVERFLOW_SIZE
        );

        bStatus = DeviceIoControl(
            hDevice,
            dwIoControlCode,
            (LPVOID)((DWORD)InvalidHeapAddress + i),
            MAX_STACKOVERFLOW_SIZE,      // Length ?
            (LPVOID)((DWORD)InvalidHeapAddress + i),
            MAX_STACKOVERFLOW_SIZE,
            &BytesReturned,
            NULL
        );

    }

    // ERROR_INVALID_FUNCTION - 1
    // ERROR_GEN_FAILURE      - 31 (0x1F)

    CloseHandle(hDevice);

    return bStatus;
}

// ---- Batch Mode

void Fuzz_Stack_Overflow_PDBI(PDIRECTORY_BASIC_INFORMATION pSymbolicLinkDirectory, DWORD dwIoControlCode, char paddingChar)
{
    char SymbolicLinkName[MAX_PATH] = {0};
    BOOL bStatus = FALSE;

    while ((pSymbolicLinkDirectory->ObjectName.Length != 0) && (pSymbolicLinkDirectory->ObjectTypeName.Length != 0))
    {
        WideCharToMultiByte(
            CP_ACP,
            0,
            pSymbolicLinkDirectory->ObjectName.Buffer,
            -1,
            SymbolicLinkName,
            sizeof(SymbolicLinkName),
            NULL,
            NULL
        );

        bStatus = Fuzz_Stack_Overflow(SymbolicLinkName, dwIoControlCode, paddingChar);

        pSymbolicLinkDirectory++;
    }

}

void Fuzz_NULL_Pointer_PDBI(PDIRECTORY_BASIC_INFORMATION pSymbolicLinkDirectory, DWORD dwIoControlCode)
{
    char SymbolicLinkName[MAX_PATH] = {0};
    BOOL bStatus = FALSE;

    while ((pSymbolicLinkDirectory->ObjectName.Length != 0) && (pSymbolicLinkDirectory->ObjectTypeName.Length != 0))
    {
        // wctomb(SymbolicLinkPath, pBufferBackup->ObjectName.Buffer);  // PWSTR -> LPCSTR
        WideCharToMultiByte(
            CP_ACP,
            0,
            pSymbolicLinkDirectory->ObjectName.Buffer,
            -1,
            SymbolicLinkName,
            sizeof(SymbolicLinkName),
            NULL,
            NULL
        );

        bStatus = Fuzz_NULL_Pointer(SymbolicLinkName, dwIoControlCode);

        pSymbolicLinkDirectory++;
    }

}

void Fuzz_Invalid_Address_PDBI(PDIRECTORY_BASIC_INFORMATION pSymbolicLinkDirectory, DWORD dwIoControlCode)
{
    char SymbolicLinkName[MAX_PATH] = {0};
    BOOL bStatus = FALSE;

    while ((pSymbolicLinkDirectory->ObjectName.Length != 0) && (pSymbolicLinkDirectory->ObjectTypeName.Length != 0))
    {
        // wctomb(SymbolicLinkPath, pBufferBackup->ObjectName.Buffer);  // PWSTR -> LPCSTR
        WideCharToMultiByte(
            CP_ACP,
            0,
            pSymbolicLinkDirectory->ObjectName.Buffer,
            -1,
            SymbolicLinkName,
            sizeof(SymbolicLinkName),
            NULL,
            NULL
        );

        bStatus = Fuzz_Invalid_Address(SymbolicLinkName, dwIoControlCode);

        pSymbolicLinkDirectory++;
    }

}

// https://osandamalith.com/2017/06/22/windows-kernel-exploitation-null-pointer-dereference/
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
// https://msdn.microsoft.com/en-us/library/b0084kay.aspx
// https://stackoverflow.com/questions/1202687/how-do-i-get-a-specific-range-of-numbers-from-rand
// https://www.geeksforgeeks.org/generating-random-number-range-c/
