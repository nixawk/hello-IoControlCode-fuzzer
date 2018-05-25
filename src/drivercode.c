/***********************************************************
* Project     : CrashMeat
* Author      : Nixawk
* Description : A Fuzz Framework for Analysis
* License     : GPL3
***********************************************************/

#include "winerr.h"
#include "driver.h"
// #include "log.h"

BOOL Crack_IoControlCode(LPCSTR SymbolicLinkName)  // Wait
{
    // An I/O control code is a 32-bit value that consists of several fields.
    // The following figure illustrates the layout of I/O control codes.


    // #define IOCTL_Device_Function CTL_CODE(DeviceType, Function, Method, Access)

    // DeviceType
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/specifying-device-types

    // FunctionCode
    // - Values of less than 0x8000 are reserved for Microsoft.
    // - Values of 0x8000 and higher can be used by vendors.

    // TransferType
    // - METHOD_BUFFERED
    // - METHOD_IN_DIRECT
    // - METHOD_OUT_DIRECT
    // - METHOD_NEITHER

    // RequiredAccess
    // - FILE_ANY_ACCESS
    // - FILE_READ_DATA
    // - FILE_WRITE_DATA

    // Example:
    // #define CTL_HEL CTL_CODE(FILE_DEVICE_UNKNOWN,0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

    return FALSE;

}

void Push_IoControlCode(PIO_CONTROL_CODE_ENTRY *pIoControlCodeEntry, DWORD Start, DWORD End)
{
	PIO_CONTROL_CODE_ENTRY pIoControlCodeEntryNew = NULL;

	pIoControlCodeEntryNew = (PIO_CONTROL_CODE_ENTRY)malloc(sizeof(IO_CONTROL_CODE_ENTRY));
	if (NULL == pIoControlCodeEntryNew)
	{
		printf("[-] Push_IoControlCode Error: malloc failed\n");
		exit(-1);
	}

	pIoControlCodeEntryNew->Start = Start;
	pIoControlCodeEntryNew->End = End;
	pIoControlCodeEntryNew->Next = *pIoControlCodeEntry;

	*pIoControlCodeEntry = pIoControlCodeEntryNew;
}


PIO_CONTROL_CODE_ENTRY ParseIoControlCodeFromOptArg(char *IoControlCodeLst)
{
	PIO_CONTROL_CODE_ENTRY pIoControlCodeEntry = NULL;

    char *IoControlCodeLstToken = NULL;
    char *IoControlCodeLstTokenParse = NULL;

    DWORD IoControlCodeIndex = 0;

    if (NULL == IoControlCodeLst)
    {
    	printf("[-] ParseIoControlCodeFromOptArg Error: no IoControlCode string\n");
    	goto CLEANUP_AND_EXIT;
    }

    IoControlCodeLstToken = strtok(IoControlCodeLst, ",");
    while (NULL != IoControlCodeLstToken)
    {
        if (NULL != strchr(IoControlCodeLstToken, '-'))
        {
            // printf("Index: %ld, IoControlCode Range  : %s\n", IoControlCodeIndex, IoControlCodeLstToken);

            // Attention: strtok will change the pointer status.
            IoControlCodeLstTokenParse = strchr(IoControlCodeLstToken, '-');
            *IoControlCodeLstTokenParse = '\0';

            Push_IoControlCode(
            	&pIoControlCodeEntry,
            	(DWORD)atoi(IoControlCodeLstToken),
            	(DWORD)atoi(IoControlCodeLstTokenParse + 1)
            );

        } else {
            // printf("Index: %ld, IoControlCode Single : %s\n", IoControlCodeIndex, IoControlCodeLstToken);

            Push_IoControlCode(
            	&pIoControlCodeEntry,
            	(DWORD)atoi(IoControlCodeLstToken),
            	(DWORD)atoi(IoControlCodeLstToken)
            );

        }

        IoControlCodeIndex += 2;

        IoControlCodeLstToken = strtok(NULL, ",");
    }

    // printf(
    //     "{"
    //         "'func': 'ParseIoControlCodeFromOptArg', "
    //         "'text': 'IoControlCode Count: %ld',"
    //     "}\n",
    //     IoControlCodeIndex / 2
    // );

    // printf("[*] IoControlCode Count, [%ld]\n", IoControlCodeIndex / 2);

    // while (NULL != pIoControlCodeEntry)
    // {
    // 	printf(
    // 		"Start: %ld, End: %ld\n",
    // 		pIoControlCodeEntry->Start,
    // 		pIoControlCodeEntry->End
    // 	);

    // 	pIoControlCodeEntry = pIoControlCodeEntry->Next;
    // }


CLEANUP_AND_EXIT:
	return pIoControlCodeEntry;

}


// https://www.thegeekstuff.com/2012/08/c-linked-list-example/
// http://www.learn-c.org/en/Linked_lists
// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
