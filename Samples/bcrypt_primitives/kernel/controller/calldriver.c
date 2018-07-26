/*++

Copyright (c) 2006-2007  Microsoft Corporation All Rights Reserved

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
PURPOSE.


Module Name:

    calldriver.c

Abstract:

    This user-mode program installs, calls, and removes the
    CNGCLIENT.SYS driver.

Author:

Environment:

    Win32 console multi-threaded application

Notes:

    To install and test the driver, move a copy of CNGCLIENT.SYS (located
    in ...\Kernel\Driver)into the same directory as CALLDRIVER.EXE. Then
    run CALLDRIVER from the command line. You will need to run this program
    from an Administrator account.

Revision History:

--*/


///////////////////////////////////////////////////////////////////////////////
//
// Headers...
//
///////////////////////////////////////////////////////////////////////////////
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cngclient.h"
#include "install.h"

///////////////////////////////////////////////////////////////////////////////
//
// Forward declarations of local routines...
//
///////////////////////////////////////////////////////////////////////////////
VOID
PrintBytes(
    __in BYTE *pbPrintData,
    __in DWORD cbDataLen
    );

///////////////////////////////////////////////////////////////////////////////
//
// Main entry point...
//
///////////////////////////////////////////////////////////////////////////////
VOID _cdecl main( ULONG argc, PCHAR argv[] )
{
    HANDLE hDevice;
    BOOL bRc;
    ULONG bytesReturned;
    DWORD win32Status = ERROR_SUCCESS;
    UCHAR driverLocation[MAX_PATH];

    char randomNumberBuffer[128];

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    //
    // open the device
    //

    if((hDevice = CreateFile(
            CNGCLIENT_USER_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL)) == INVALID_HANDLE_VALUE)
    {
        win32Status = GetLastError();

        if (win32Status != ERROR_FILE_NOT_FOUND)
        {
            printf("Error: CreatFile Failed : %d\n", win32Status);
            return ;
        }

        //
        // The driver is not started yet so let us the install the driver.
        // First setup full path to driver name.
        //

        if (!SetupDriverName(driverLocation, (PUCHAR)CNGCLIENT_DRIVER_NAME))
        {
            return ;
        }

        if (!ManageDriver(CNGCLIENT_DRIVER_NAME,
                          (LPCTSTR)driverLocation,
                          DRIVER_FUNC_INSTALL
                          ))
        {
            printf("Unable to install driver. \n");
            goto Cleanup;
        }

        hDevice = CreateFile(
                    CNGCLIENT_USER_DEVICE_NAME,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    NULL,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL);

        if ( hDevice == INVALID_HANDLE_VALUE )
        {
            printf ( "Error: CreatFile Failed : %d\n", GetLastError());
            goto Cleanup;
        }
    }

    //
    // Send IOCTL_CNGCLIENT_GEN_RANDOM to driver
    //

    printf("\nSending IOCTL_CNGCLIENT_GEN_RANDOM command:\n\n");

    ZeroMemory(randomNumberBuffer, sizeof(randomNumberBuffer));

    bRc = DeviceIoControl(
                hDevice,
                (DWORD) IOCTL_CNGCLIENT_GEN_RANDOM,
                NULL,           // no input buffer
                0,
                &randomNumberBuffer,
                sizeof( randomNumberBuffer),
                &bytesReturned,
                NULL
                );

    if ( !bRc )
    {
        printf ( "Error in DeviceIoControl : %d", GetLastError());
        goto Cleanup;
    }

    PrintBytes((BYTE*)randomNumberBuffer, bytesReturned);
    printf("\n");

Cleanup:

    CloseHandle ( hDevice );

    //
    // Unload the driver.  Ignore any errors.
    //

    ManageDriver(CNGCLIENT_DRIVER_NAME,
                 (LPCTSTR)driverLocation,
                 DRIVER_FUNC_REMOVE
                 );
}
///////////////////////////////////////////////////////////////////////////////


VOID
PrintBytes(
    __in BYTE     *pbPrintData,
    __in DWORD    cbDataLen
    )
{
    DWORD dwCount = 0;

    for(dwCount=0; dwCount < cbDataLen;dwCount++)
    {
        printf("0x%02x, ",pbPrintData[dwCount]);

        if(0 == (dwCount + 1 )%10) putchar('\n');
    }
}
///////////////////////////////////////////////////////////////////////////////



