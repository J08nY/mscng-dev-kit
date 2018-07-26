/*++

Copyright (c) 2006-2007  Microsoft Corporation All Rights Reserved

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
PURPOSE.


Module Name:

    cngclient.h

Abstract:
  
    This header defines the IOCTL codes recognized by the driver, along
    with some well-known names needed by the driver and its user-mode 
    caller.

Author:

Environment:

    Shared between kernel-mode driver and its user-mode caller.

Notes:

Revision History:

--*/

#define CNGCLIENT_DRIVER_NAME           "cngclient"
//#define CNGCLIENT_DRIVER_FILE_NAME      L"cngclient.sys"

#define CNGCLIENT_NT_DEVICE_NAME        L"\\Device\\CngClient0"
#define CNGCLIENT_WIN32_DEVICE_NAME     L"\\DosDevices\\CNGCLIENT"

#define CNGCLIENT_USER_DEVICE_NAME      "\\\\.\\CNGCLIENT"

//
// Device type           -- in the "User Defined" range."
//
#define CNGCLIENT_TYPE 40000

//
// Define IOCTL codes recognized by the cngclient driver. The 
// IOCTL values from 0x800 to 0xFFF are for customer use...
//
#define IOCTL_CNGCLIENT_GEN_RANDOM \
    CTL_CODE( CNGCLIENT_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS  )


