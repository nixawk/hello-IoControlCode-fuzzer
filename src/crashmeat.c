/***********************************************************
* Project     : CrashMeat
* Author      : Nixawk
* Description : A Fuzz Framework for Analysis
* License     : GPL3
***********************************************************/

/* OUTPUT

{'func': '', 'text': '', ...}
{'func': '', 'error': '', 'code': ''}

*/

#include "winerr.h"
#include "getopt.h"
#include "driver.h"
// #include "log.h"


void banner()
{
    printf("\n"
        "   _____               _       __  __            _        \n"
        "  / ____|             | |     |  \\/  |          | |      \n"
        " | |     _ __ __ _ ___| |__   | \\  / | ___  __ _| |_     \n"
        " | |    | '__/ _` / __| '_ \\  | |\\/| |/ _ \\/ _` | __|  \n"
        " | |____| | | (_| \\__ \\ | | | | |  | |  __/ (_| | |_    \n"
        "  \\_____|_|  \\__,_|___/_| |_| |_|  |_|\\___|\\__,_|\\__|\n"
        "\n"
        "                                             [Nixawk]\n"
        "\n"
        );
}

void usage(char *programname)
{
    banner();
    printf(
        "  Usage\n"
        "  -----\n"
        "\n"
        "  :: Help\n"
        "     -h/-? Show help information\n"
        "\n"
        "  :: Enum Drivers\n"
        "     -l    List all drivers name and status in system.\n"
        "\n"
        "  :: Load Drivers\n"
        "     -a    Load all drivers in system automatically\n"
        "     -d    <SymbolicLinkName> Load a driver with symlink name\n"
        "\n"
        "  :: Load Io Control Code\n"
        "     -c    Input available io control code, split with dot (ex: 1,3-5)\n"
        "     -b    Bruteforce io control code\n"
        "\n"
        "  :: Fuzz Mode\n"
        "     -n    Null Pointer Fuzz\n"
        "     -s    Stack Overflow Fuzz\n"
        "     -i    Invalid Address Fuzz\n"
        "\n"
        "  :: Verbose Mode\n"
        "     -v    Make the operation more talkative\n"
        "\n",
        programname
    );

    // exit(-1);
}


int
main(int argc, char *argv[])
{
    int getoptval;

    BOOL Switch_Enum_Drivers = FALSE;
    BOOL Switch_Load_Drivers_a = FALSE;
    BOOL Switch_Load_IoControlCode_c = FALSE;       // Input IoControlCoe
    BOOL Switch_Load_IoControlCode_b = FALSE;       // IoControlCode bruteforce or not
    BOOL Switch_Fuzz_Mode_n = FALSE;                // fuzz mode - null pointer
    BOOL Switch_Fuzz_Mode_s = FALSE;                // fuzz mode - stack overflow
    BOOL Switch_Fuzz_Mode_i = FALSE;                // fuzz mode - invalid address

    char *SymbolicLinkName = NULL;

    char *IoControlCodeOptArg = NULL;

    PIO_CONTROL_CODE_ENTRY pIoControlCodeEntry = NULL;   // List Entry
    PDIRECTORY_BASIC_INFORMATION pSymbolicLinkDirectory = NULL;  // List Entry

    DWORD FuzzIndex; // Index

    char stack_overflow_padding_char = 'A';

    while ((getoptval = getopt(argc, argv, "d:c:r:labnsih?v")) != -1)
    {
        switch(getoptval)
        {
            case 'l':    // List all drivers
                Switch_Enum_Drivers = TRUE;
                break;

            case 'a':    // analysis automatically
                Switch_Load_Drivers_a = TRUE;
                break;

            case 'd':    // input a driver symbolic name
                SymbolicLinkName = optarg;
                break;

            case 'c':    // input 
                Switch_Load_IoControlCode_c = TRUE;
                IoControlCodeOptArg = optarg;
                break;

            case 'b':
                Switch_Load_IoControlCode_b = TRUE;
                break;

            case 'n':
                Switch_Fuzz_Mode_n = TRUE;
                break;

            case 's':
                Switch_Fuzz_Mode_s = TRUE;
                break;

            case 'i':
                Switch_Fuzz_Mode_i = TRUE;
                break;

            case 'v':
                break;

            case 'h':
            case '?':
                break;
        }
    }

    // list all available symbolic links or not
    if (Switch_Enum_Drivers)
    {
        PrintAllDriverSymbolicLink();
        exit(0);
    }

    // 1. Get a valid symbolic link name
    if (NULL == SymbolicLinkName && !Switch_Load_Drivers_a)
    {
        usage(argv[0]);
        printf(
            "{"
                "'func': 'main', "
                "'error': 'Please set a Load Drivers option',"
                "'code': 1111"
            "}\n");
        exit(-1);
    }

    // 2. Get a valid io control code
    if (NULL == IoControlCodeOptArg && !Switch_Load_IoControlCode_b)
    {
        usage(argv[0]);
        printf(
            "{"
                "'func': 'main', "
                "'error': 'Please set a Load Io Control Code option',"
                "'code': 1111"
            "}\n");
        exit(-1);
    }

    if (Switch_Load_IoControlCode_c)
        pIoControlCodeEntry = ParseIoControlCodeFromOptArg(IoControlCodeOptArg);

    if (NULL == pIoControlCodeEntry)
    {
        printf(
            "{"
                "'func': 'main', "
                "'error': 'Fail to get a Io Control Code',"
                "'code': 1111"
            "}\n");
        exit(-1);
    }

    if (Switch_Load_IoControlCode_b)
        printf("[*] Bruteforce IoControlCode will be in the future\n");

    // 3. Fuzz

    if (!Switch_Fuzz_Mode_n && !Switch_Fuzz_Mode_s && !Switch_Fuzz_Mode_i)
    {
        printf(
            "{"
                "'func': 'main', "
                "'error': 'Please set a Fuzz Mode option',"
                "'code': 1111"
            "}\n");
        exit(-1);
    }

    if (Switch_Load_Drivers_a)  // auto analysis all drivers
        pSymbolicLinkDirectory = GetAllDriversSymbolicLink();

    while (NULL != pIoControlCodeEntry)
    {

        // printf(
        //     "{"
        //         "'func': 'main', "
        //         "'text': 'IoControlCode range, [%08x, %08X]',"
        //     "}\n",
        //     pIoControlCodeEntry->Start, pIoControlCodeEntry->End
        // );

        // printf(
        //     "[*] IoControlCode Range, [Start: %08x, End: %08X]\n",
        //     pIoControlCodeEntry->Start, pIoControlCodeEntry->End
        // );

        if (pIoControlCodeEntry->Start >= pIoControlCodeEntry->End)
        {
            pIoControlCodeEntry->Start ^= pIoControlCodeEntry->End;
            pIoControlCodeEntry->End ^= pIoControlCodeEntry->Start;
            pIoControlCodeEntry->Start ^= pIoControlCodeEntry->End;
        }

        // Fuzz a single driver
        if (NULL != SymbolicLinkName && AccessDriverBySymbolicLinkName(SymbolicLinkName))
        {
            for (FuzzIndex = pIoControlCodeEntry->Start; FuzzIndex <= pIoControlCodeEntry->End; FuzzIndex++)
            {
                if (Switch_Fuzz_Mode_n)
                    Fuzz_NULL_Pointer(SymbolicLinkName, FuzzIndex);

                if (Switch_Fuzz_Mode_s)
                    Fuzz_Stack_Overflow(SymbolicLinkName, FuzzIndex, stack_overflow_padding_char);

                if (Switch_Fuzz_Mode_i)
                    Fuzz_Invalid_Address(SymbolicLinkName, FuzzIndex);
            }
        }


        // Fuzz multi fuzz
        if (NULL != pSymbolicLinkDirectory)
        {
            for (FuzzIndex = pIoControlCodeEntry->Start; FuzzIndex <= pIoControlCodeEntry->End; FuzzIndex++)
            {

            // All Driver - Fuzz

                if (Switch_Fuzz_Mode_n)
                    Fuzz_NULL_Pointer_PDBI(pSymbolicLinkDirectory, FuzzIndex);

                if (Switch_Fuzz_Mode_s)
                    Fuzz_Stack_Overflow_PDBI(pSymbolicLinkDirectory, FuzzIndex, stack_overflow_padding_char);

                if (Switch_Fuzz_Mode_i)
                    Fuzz_Invalid_Address_PDBI(pSymbolicLinkDirectory, FuzzIndex);

           }
        }

        pIoControlCodeEntry = pIoControlCodeEntry->Next;
    }

    return 0;
}


// https://stackoverflow.com/questions/2519851/how-to-deal-with-warning-c4100-in-visual-studio-2008
// https://stackoverflow.com/questions/133698/why-does-fatal-error-lnk1104-cannot-open-file-c-program-obj-occur-when-i-c
// https://stackoverflow.com/questions/3889992/how-does-strtok-split-the-string-into-tokens-in-c
// https://github.com/rxi/log.c/
// https://stackoverflow.com/questions/10017272/programming-with-verbose-option-in-c
