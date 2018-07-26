/*++

Copyright (c) 2006-2007  Microsoft Corporation All Rights Reserved

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
PURPOSE.


Module Name:

    install.h

Abstract:
  
    This header defines the public interface exposed by the
    driver-installation routines.

Author:

Environment:

    User mode.

Notes:

Revision History:

--*/


///////////////////////////////////////////////////////////////////////////////
//
// Command codes recognized by the ManageDriver function...
//
///////////////////////////////////////////////////////////////////////////////
#define DRIVER_FUNC_INSTALL     0x01
#define DRIVER_FUNC_REMOVE      0x02


///////////////////////////////////////////////////////////////////////////////
//
// Public API...
//
///////////////////////////////////////////////////////////////////////////////
BOOLEAN
ManageDriver(
    __in LPCTSTR  DriverName,
    __in LPCTSTR  ServiceName,
    __in USHORT   CommandCode
    );

BOOLEAN
SetupDriverName(
    __inout CHAR DriverLocation[MAX_PATH],
    __in  PUCHAR DriverName
    );
