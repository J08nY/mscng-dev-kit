/*++

Copyright (c) 2006-2007  Microsoft Corporation All Rights Reserved

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
PURPOSE.


Module Name:

    install.c

Abstract:

    This user-mode program installs, calls, and removes the
    CNGCLIENT.SYS driver.

Author:

Environment:

    Win32 console multi-threaded application

Notes:

    To install and test the driver, move a copy of CNGCLIENT.SYS into the
    same directory as CALLDRIVER.EXE. Then run CALLDRIVER from the command
    line. You will need to run this program under an Administrator account.

Revision History:

--*/


///////////////////////////////////////////////////////////////////////////////
//
// Headers...
//
///////////////////////////////////////////////////////////////////////////////
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cngclient.h"
#include "install.h"

///////////////////////////////////////////////////////////////////////////////
//
// Local definitions...
//
///////////////////////////////////////////////////////////////////////////////
#ifndef ARGUMENT_PRESENT
#define ARGUMENT_PRESENT(x) ((x) != NULL)
#endif


///////////////////////////////////////////////////////////////////////////////
//
// Forward declarations of local functions...
//
///////////////////////////////////////////////////////////////////////////////
static BOOLEAN
InstallDriver(
    __in SC_HANDLE  SchSCManager,
    __in LPCTSTR    DriverName,
    __in LPCTSTR    ServiceExe
    );


static BOOLEAN
RemoveDriver(
    __in SC_HANDLE  SchSCManager,
    __in LPCTSTR    DriverName
    );

static BOOLEAN
StartDriver(
    __in SC_HANDLE  SchSCManager,
    __in LPCTSTR    DriverName
    );

static BOOLEAN
StopDriver(
    __in SC_HANDLE  SchSCManager,
    __in LPCTSTR    DriverName
    );


///////////////////////////////////////////////////////////////////////////////
//
// Public API for this module...
//
///////////////////////////////////////////////////////////////////////////////
BOOLEAN
ManageDriver(
    __in LPCTSTR  DriverName,
    __in LPCTSTR  ServiceName,
    __in USHORT   CommandCode
    )
{

    SC_HANDLE   schSCManager;

    BOOLEAN rCode = TRUE;

    //
    // Insure (somewhat) that the driver and service names are valid.
    //

    if (!ARGUMENT_PRESENT(DriverName) || !ARGUMENT_PRESENT(ServiceName))
    {
        printf("Invalid Driver or Service provided to ManageDriver() \n");
        return FALSE;
    }

    //
    // Connect to the Service Control Manager and open the Services database.
    //

    schSCManager = OpenSCManager(
                        NULL,                   // local machine
                        NULL,                   // local database
                        SC_MANAGER_ALL_ACCESS   // access required
                        );
    if (!schSCManager)
    {
        printf("Open SC Manager failed! Error = %d \n", GetLastError());
        return FALSE;
    }

    //
    // Do the requested function.
    //

    switch( CommandCode )
    {
    case DRIVER_FUNC_INSTALL:

        //
        // Install the driver service.
        //

        if (InstallDriver(schSCManager,
                          DriverName,
                          ServiceName
                          ))
        {
            //
            // Start the driver service (i.e. start the driver).
            //

            rCode = StartDriver(schSCManager,
                                DriverName
                                );
        }
        else
        {
            //
            // Indicate an error.
            //

            rCode = FALSE;
        }
        break;

    case DRIVER_FUNC_REMOVE:

            //
            // Stop the driver.
            //

            StopDriver(schSCManager,
                       DriverName
                       );

            //
            // Remove the driver service.
            //

            RemoveDriver(schSCManager,
                         DriverName
                         );

            //
            // Ignore all errors.
            //

            rCode = TRUE;
            break;

    default:

            printf("Unknown ManageDriver() function. \n");
            rCode = FALSE;
            break;
    }

    //
    // Close handle to service control manager.
    //

    if (schSCManager)
    {
        CloseServiceHandle(schSCManager);
    }
    return rCode;
}
///////////////////////////////////////////////////////////////////////////////


BOOLEAN
SetupDriverName(
    __inout CHAR DriverLocation[MAX_PATH],
    __in PUCHAR DriverName
    )
{
    HANDLE fileHandle;
    DWORD driverLocLen = 0;
	
    //
    // Get the current directory.
    //

    driverLocLen = GetCurrentDirectory(MAX_PATH, (LPSTR)DriverLocation );
    if (!driverLocLen)
    {
        printf("GetCurrentDirectory failed!  Error = %d \n", GetLastError());
        return FALSE;
    }

    //
    // Setup path name to driver file.
    //

    strcat_s((char*)DriverLocation,MAX_PATH,"\\");
    strcat_s((char*)DriverLocation,MAX_PATH,(const char*)DriverName);
    strcat_s((char*)DriverLocation,MAX_PATH, ".sys");

    //
    // Insure driver file is in the specified directory.
    //

    if ((fileHandle = CreateFile((LPCSTR)DriverLocation,
                                 GENERIC_READ,
                                 0,
                                 NULL,
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL,
                                 NULL
                                 )) == INVALID_HANDLE_VALUE)
    {
        printf("Driver: %s.sys is not in the %s directory. \n", DriverName, DriverLocation );

        //
        // Indicate failure.
        //

        return FALSE;
    }

    //
    // Close open file handle.
    //

    if (fileHandle)
    {
        CloseHandle(fileHandle);
    }

    //
    // Indicate success.
    //

    return TRUE;
}
///////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////
//
// Helper routines...
//
///////////////////////////////////////////////////////////////////////////////
BOOLEAN
InstallDriver(
    __in SC_HANDLE  SchSCManager,
    __in LPCTSTR    DriverName,
    __in LPCTSTR    ServiceExe
    )
/*++

Routine Description:

Arguments:

Return Value:

--*/
{
    SC_HANDLE   schService;
    DWORD       err;

    //
    // NOTE: This creates an entry for a standalone driver. If this
    //       is modified for use with a driver that requires a Tag,
    //       Group, and/or Dependencies, it may be necessary to
    //       query the registry for existing driver information
    //       (in order to determine a unique Tag, etc.).
    //

    //
    // Create a new a service object.
    //

    schService = CreateService(SchSCManager,           // handle of service control manager database
                               DriverName,             // address of name of service to start
                               DriverName,             // address of display name
                               SERVICE_ALL_ACCESS,     // type of access to service
                               SERVICE_KERNEL_DRIVER,  // type of service
                               SERVICE_DEMAND_START,   // when to start service
                               SERVICE_ERROR_NORMAL,   // severity if service fails to start
                               ServiceExe,             // address of name of binary file
                               NULL,                   // service does not belong to a group
                               NULL,                   // no tag requested
                               NULL,                   // no dependency names
                               NULL,                   // use LocalSystem account
                               NULL                    // no password for service account
                               );

    if (schService == NULL)
    {
        err = GetLastError();

        if (err == ERROR_SERVICE_EXISTS)
        {
            //
            // Ignore this error.
            //

            return TRUE;
        }
        else
        {
            printf("CreateService failed!  Error = %d \n", err );

            //
            // Indicate an error.
            //

            return  FALSE;
        }
    }

    //
    // Close the service object.
    //

    if (schService)
    {
        CloseServiceHandle(schService);
    }

    //
    // Indicate success.
    //

    return TRUE;
}
///////////////////////////////////////////////////////////////////////////////


BOOLEAN
RemoveDriver(
    __in SC_HANDLE    SchSCManager,
    __in LPCTSTR      DriverName
    )
{
    SC_HANDLE   schService;
    BOOLEAN     rCode;

    //
    // Open the handle to the existing service.
    //

    schService = OpenService(SchSCManager,
                             DriverName,
                             SERVICE_ALL_ACCESS
                             );
    if (schService == NULL)
    {
        printf("OpenService failed!  Error = %d \n", GetLastError());

        //
        // Indicate error.
        //

        return FALSE;
    }

    //
    // Mark the service for deletion from the service control manager database.
    //

    if (DeleteService(schService))
    {
        //
        // Indicate success.
        //

        rCode = TRUE;
    }
    else
    {
        printf("DeleteService failed!  Error = %d \n", GetLastError());

        //
        // Indicate failure.  Fall through to properly close the service handle.
        //

        rCode = FALSE;
    }

    //
    // Close the service object.
    //

    if (schService)
    {
        CloseServiceHandle(schService);
    }

    return rCode;
}
///////////////////////////////////////////////////////////////////////////////


BOOLEAN
StartDriver(
    __in  SC_HANDLE    SchSCManager,
    __in  LPCTSTR      DriverName
    )
{
    SC_HANDLE   schService;
    DWORD       err;

    //
    // Open the handle to the existing service.
    //

    schService = OpenService(SchSCManager,
                             DriverName,
                             SERVICE_ALL_ACCESS
                             );
    if (schService == NULL)
    {
        printf("OpenService failed!  Error = %d \n", GetLastError());

        //
        // Indicate failure.
        //

        return FALSE;
    }

    //
    // Start the execution of the service (i.e. start the driver).
    //

    if (!StartService(schService,     // service identifier
                      0,              // number of arguments
                      NULL            // pointer to arguments
                      ))
    {
        err = GetLastError();

        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {

            //
            // Ignore this error.
            //

            return TRUE;
        }
        else
        {
            printf("StartService failure! Error = %d \n", err );

            //
            // Indicate failure.  Fall through to properly close the service handle.
            //

            return FALSE;
        }
    }

    //
    // Close the service object.
    //

    if (schService)
    {
        CloseServiceHandle(schService);
    }
    return TRUE;
}
///////////////////////////////////////////////////////////////////////////////


BOOLEAN
StopDriver(
    __in SC_HANDLE    SchSCManager,
    __in LPCTSTR      DriverName
    )
{
    BOOLEAN         rCode = TRUE;
    SC_HANDLE       schService;
    SERVICE_STATUS  serviceStatus;

    //
    // Open the handle to the existing service.
    //

    schService = OpenService(SchSCManager,
                             DriverName,
                             SERVICE_ALL_ACCESS
                             );
    if (schService == NULL)
    {
        printf("OpenService failed!  Error = %d \n", GetLastError());
        return FALSE;
    }

    //
    // Request that the service stop.
    //

    if (ControlService(schService,
                       SERVICE_CONTROL_STOP,
                       &serviceStatus
                       ))
    {
        //
        // Indicate success.
        //

        rCode = TRUE;
    }
    else
    {
        printf("ControlService failed!  Error = %d \n", GetLastError() );

        //
        // Indicate failure.  Fall through to properly close the service handle.
        //

        rCode = FALSE;
    }

    //
    // Close the service object.
    //

    if (schService)
    {
        CloseServiceHandle (schService);
    }
    return rCode;
}
///////////////////////////////////////////////////////////////////////////////

