/***********************************************************
* Project     : CrashMeat
* Author      : Nixawk
* Description : A Fuzz Framework for Analysis
* License     : GPL3
***********************************************************/

#pragma once

#ifndef _DRIVER_
#define _DRIVER_

#include <windows.h>  
#include <stdlib.h>  
#include <stdio.h>  

// https://doxygen.reactos.org/db/ded/reactos_2wine_2winternl_8h_source.html#l00001
// typedef ULONG NTSTATUS;
typedef LONG NTSTATUS;

// https://doxygen.reactos.org/dd/df3/env__spec__w32_8h_source.html#l00368
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

// https://doxygen.reactos.org/da/dc1/umtypes_8h_source.html#l00169
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// https://doxygen.reactos.org/db/ded/reactos_2wine_2winternl_8h_source.html#l02148 
typedef struct _DIRECTORY_BASIC_INFORMATION {
    UNICODE_STRING ObjectName;
    UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;

// https://doxygen.reactos.org/d2/dea/psdk_2winternl_8h_source.html#l00228
#define OBJ_INHERIT                0x00000002L
#define OBJ_PERMANENT              0x00000010L
#define OBJ_EXCLUSIVE              0x00000020L
#define OBJ_CASE_INSENSITIVE       0x00000040L
#define OBJ_OPENIF                 0x00000080L
#define OBJ_OPENLINK               0x00000100L
#define OBJ_KERNEL_HANDLE          0x00000200L
#define OBJ_FORCE_ACCESS_CHECK     0x00000400L
#define OBJ_VALID_ATTRIBUTES       0x000007F2L

// https://doxygen.reactos.org/dd/da0/om_8c_source.html#l00211
#define DIRECTORY_QUERY            (0x0001)
#define SYMBOLIC_LINK_QUERY        0x0001

// https://doxygen.reactos.org/df/db3/udferr__usr_8h_source.html#l00124
#define STATUS_SUCCESS             ((NTSTATUS)0x00000000L)
#define STATUS_MORE_ENTRIES        ((NTSTATUS)0x00000105L)
#define STATUS_BUFFER_TOO_SMALL    ((NTSTATUS)0xC0000023L)

// https://doxygen.reactos.org/de/d63/modules_2rostests_2winetests_2ntdll_2reg_8c_source.html#l00106
#define InitializeObjectAttributes(p,n,a,r,s) \
    do { \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory = r; \
        (p)->Attributes = a; \
        (p)->ObjectName = n; \
        (p)->SecurityDescriptor = s; \
        (p)->SecurityQualityOfService = NULL; \
    } while (0)

// https://doxygen.reactos.org/de/d46/tunneltest_8c_source.html#l00014
#define RTL_CONSTANT_STRING(s) { sizeof(s)-sizeof((s)[0]), sizeof(s), s }

// https://doxygen.reactos.org/db/dc9/nt__native_8h.html#a5e6d7af51cb6d106401f3967b6b44b12
// https://www.sysnative.com/forums/programming/8592-ntcreatefile-example.html
typedef VOID(CALLBACK* RTLINITUNICODESTRING)(
   PUNICODE_STRING DestinationString,
   PCWSTR          SourceString
);

// https://doxygen.reactos.org/de/df6/ndk_2obfuncs_8h.html#a409c7b692423f91807fbf39cb2c79555
typedef NTSTATUS(WINAPI *ZWOPENDIRECTORYOBJECT)(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

// https://msdn.microsoft.com/en-us/library/bb470238(v=vs.85).aspx
typedef NTSTATUS(WINAPI *ZWQUERYDIRECTORYOBJECT)(
    IN     HANDLE  DirectoryHandle,
    OUT    PVOID   Buffer,
    IN     ULONG   BufferLength,
    IN     BOOLEAN ReturnSingleEntry,
    IN     BOOLEAN RestartScan,
    IN OUT PULONG  Context,
    OUT    PULONG  ReturnLength OPTIONAL
);

// https://doxygen.reactos.org/de/df6/ndk_2obfuncs_8h.html#a5e0a128a3b03af9e6deef339000e30e0
typedef NTSTATUS(WINAPI *ZWCLOSE)(
    IN HANDLE Handle
);


typedef struct _IO_CONTROL_CODE_ENTRY {
    DWORD Start;
    DWORD End;
    struct _IO_CONTROL_CODE_ENTRY * Next;
} IO_CONTROL_CODE_ENTRY, *PIO_CONTROL_CODE_ENTRY;


// https://stackoverflow.com/questions/5351919/how-many-chars-can-be-in-a-char-array
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/limits.h

// ---- Functions Here ----

// [[ ---- driverenum.c
// Get All Available Device Drivers from OS System
extern HANDLE OpenDriverBySymbolicLinkName(LPCSTR SymbolicLinkName);
extern BOOL AccessDriverBySymbolicLinkName(LPCSTR SymbolicLinkName);
extern PDIRECTORY_BASIC_INFORMATION GetAllDriversSymbolicLink();
extern void PrintAllDriverSymbolicLink();
// driverenum.c ---- ]]

// [[ ---- drivercode.c
extern PIO_CONTROL_CODE_ENTRY ParseIoControlCodeFromOptArg(char *IoControlCodeLst);
// drivercode.c ---- ]]


// [[ ---- driverfuzz.c
#ifndef MAX_STACKOVERFLOW_SIZE
#define MAX_STACKOVERFLOW_SIZE  0x10000   // 0xFFFF == 65535
#endif

#ifndef MAX_HEAPADDRESS_COUNT             // Heap Address Count to malloc
#define MAX_HEAPADDRESS_COUNT 30
#endif

extern BOOL Crack_IoControlCode(LPCSTR SymbolicLinkName);
extern BOOL Fuzz_NULL_Pointer(LPCSTR SymbolicLinkName, DWORD dwIoControlCode);
extern BOOL Fuzz_Stack_Overflow(LPCSTR SymbolicLinkName, DWORD dwIoControlCode, char paddingChar);
extern BOOL Fuzz_Invalid_Address(LPCSTR SymbolicLinkName, DWORD dwIoControlCode);

extern void Fuzz_NULL_Pointer_PDBI(PDIRECTORY_BASIC_INFORMATION pSymbolicLinkDirectory, DWORD dwIoControlCode);
extern void Fuzz_Stack_Overflow_PDBI(PDIRECTORY_BASIC_INFORMATION pSymbolicLinkDirectory, DWORD dwIoControlCode, char paddingChar);
extern void Fuzz_Invalid_Address_PDBI(PDIRECTORY_BASIC_INFORMATION pSymbolicLinkDirectory, DWORD dwIoControlCode);

// driverfuzz.c ---- ]]

#endif