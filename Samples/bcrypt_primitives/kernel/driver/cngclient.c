/*++

Copyright (c) 2006-2007  Microsoft Corporation All Rights Reserved

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
PURPOSE.


Module Name:

    cngclient.c

Abstract:

    This sample demonstrates the use of CNG primitive functions from
    within a kernel-mode environment.

Author:

Environment:

    Kernel mode only.

Notes:

    Most of the code in this source file is just boilerplate required
    by a minimal NT driver. All the BCRYPT-specific material is in the
    'CngClientHandleGenRandomRequest' function.

    This sample must be built using the Windows DDK.

    To install and test the driver, move a copy of CNGCLIENT.SYS into
    the same directory as CALLDRIVER.EXE (located in ...\Kernel\Controller).
    Then run CALLDRIVER from the command line. You will need to run this
    program from an Administrator account.

Revision History:

--*/


///////////////////////////////////////////////////////////////////////////////
//
// Headers...
//
///////////////////////////////////////////////////////////////////////////////
#include <ntddk.h>
#include <string.h>
#include <bcrypt.h>

#include "cngclient.h"


///////////////////////////////////////////////////////////////////////////////
//
// Misc. local definitions...
//
///////////////////////////////////////////////////////////////////////////////
#if DBG
#define CNGCLIENT_KDPRINT(_x_) \
                DbgPrint("CNGCLIENT.SYS: ");\
                DbgPrint _x_;
#else
#define CNGCLIENT_KDPRINT(_x_)
#endif


///////////////////////////////////////////////////////////////////////////////
//
// Forward declarations of driver routines...
//
///////////////////////////////////////////////////////////////////////////////
NTSTATUS
DriverEntry(
    IN OUT PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING      RegistryPath
    );

VOID
CngClientUnloadDriver(
    IN PDRIVER_OBJECT       DriverObject
    );

NTSTATUS
CngClientCreateClose(
    IN PDEVICE_OBJECT       DeviceObject,
    IN PIRP                 Irp
    );

NTSTATUS
CngClientDeviceControl(
    IN PDEVICE_OBJECT       DeviceObject,
    IN PIRP                 Irp
    );

NTSTATUS
CngClientHandleGenRandomRequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    );


///////////////////////////////////////////////////////////////////////////////
//
// Declare driver routines' memory-management attributes...
//
///////////////////////////////////////////////////////////////////////////////
#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )

#pragma alloc_text( PAGE, CngClientUnloadDriver)
#pragma alloc_text( PAGE, CngClientCreateClose)
#pragma alloc_text( PAGE, CngClientDeviceControl)
#pragma alloc_text( PAGE, CngClientHandleGenRandomRequest)

#endif // ALLOC_PRAGMA


///////////////////////////////////////////////////////////////////////////////
//
// Main entry point...
//
///////////////////////////////////////////////////////////////////////////////
NTSTATUS
DriverEntry(
    IN OUT PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING      RegistryPath
    )
/*++

Routine Description:
    This routine is called by the I/O Manager to initialize the driver.

    It creates the Device object, fills in the dispatch entry points and
    completes the initialization.

Arguments:

    DriverObject - a pointer to the object that represents this device
    driver.

    RegistryPath - a pointer to our Services key in the registry.

Return Value:

    STATUS_SUCCESS if initialized; an error otherwise.

--*/

{
    NTSTATUS        ntStatus = STATUS_SUCCESS;
    UNICODE_STRING  ntDeviceName;               // NT OS name: "\Device\CNGCLIENT"
    UNICODE_STRING  win32DeviceName;            // Win32 name: "\DosDevices\CngClient"
    PDEVICE_OBJECT  deviceObject = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);
    RtlInitUnicodeString( &ntDeviceName, CNGCLIENT_NT_DEVICE_NAME );

    ntStatus = IoCreateDevice(
                    DriverObject,               // Our Driver object
                    0,                          // No device extension
                    &ntDeviceName,              // Device name "\Device\CngClient0"
                    FILE_DEVICE_UNKNOWN,        // Device type
                    FILE_DEVICE_SECURE_OPEN,    // Device characteristics
                    FALSE,                      // Not an exclusive device
                    &deviceObject );            // Returned ptr to Device object

    if (!NT_SUCCESS( ntStatus ))
    {
        CNGCLIENT_KDPRINT(("Couldn't create the Device object\n"));
        return ntStatus;
    }

    //
    // Initialize the Driver object with this driver's entry points.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE]          = CngClientCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = CngClientCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = CngClientDeviceControl;

    DriverObject->DriverUnload = CngClientUnloadDriver;

    //
    // Build a Unicode String containing our device's Win32 name.
    //

    RtlInitUnicodeString( &win32DeviceName, CNGCLIENT_WIN32_DEVICE_NAME );

    //
    // Create a symbolic link between the NT OS device name and the Win32 name.
    //

    ntStatus = IoCreateSymbolicLink( &win32DeviceName, &ntDeviceName );
    if (!NT_SUCCESS( ntStatus ))
    {
        CNGCLIENT_KDPRINT(("Couldn't create symbolic link\n"));

        //
        // Delete everything that this routine has allocated.
        //

        IoDeleteDevice( deviceObject );
    }
    return ntStatus;
}
///////////////////////////////////////////////////////////////////////////////


VOID
CngClientUnloadDriver(
    IN PDRIVER_OBJECT DriverObject
    )
/*++

Routine Description:

    This routine is called by the I/O Manager to unload the driver.

    Any resources previously allocated must be freed.

Arguments:

    DriverObject - a pointer to the object that represents our driver.

Return Value:

    None
--*/

{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING win32DeviceName;

    //
    // Build a Unicode String containing our device's Win32 name.
    //

    RtlInitUnicodeString( &win32DeviceName, CNGCLIENT_WIN32_DEVICE_NAME );

    //
    // Remove the Win32 name from the Object Manager's namespace.
    //

    IoDeleteSymbolicLink( &win32DeviceName );

    if ( deviceObject != NULL )
    {
        IoDeleteDevice( deviceObject );
    }
}
///////////////////////////////////////////////////////////////////////////////


NTSTATUS
CngClientCreateClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
/*++

Routine Description:

    This routine is called by the I/O MANAGER when the CNGCLIENT device
    is opened or closed.

    No action is performed other than completing the request successfully.

Arguments:

    DeviceObject - a pointer to the object that represents the device
    being opened or closed.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    STATUS_SUCCESS always.

--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}
///////////////////////////////////////////////////////////////////////////////


NTSTATUS
CngClientDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
/*++

Routine Description:

    This routine is called by the I/O system to perform an IOCTL function.

Arguments:

    DeviceObject - a pointer to the object that represents the device
        that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/
{
    NTSTATUS            ntStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION  irpStack;

    Irp->IoStatus.Information = 0;

    //
    // Determine which I/O control code was specified.
    //

    irpStack = IoGetCurrentIrpStackLocation( Irp );

    switch ( irpStack->Parameters.DeviceIoControl.IoControlCode )
    {
    case IOCTL_CNGCLIENT_GEN_RANDOM:

        ntStatus = CngClientHandleGenRandomRequest( DeviceObject, Irp);
        break;

    default:

        //
        // The specified I/O control code is unrecognized by this driver.
        //

        CNGCLIENT_KDPRINT(("ERROR: unrecognized IOCTL %x\n",
            irpStack->Parameters.DeviceIoControl.IoControlCode));

        ntStatus = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    //
    // We're all done with this request. Put some status information
    // into the IRP and give ownership of it back to the I/O Manager.
    //

    Irp->IoStatus.Status = ntStatus;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return ntStatus;
}
///////////////////////////////////////////////////////////////////////////////


NTSTATUS
CngClientHandleGenRandomRequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
/*++

Routine Description:

    This routine handles the processing of IOCTL_CNGCLIENT_GEN_RANDOM
    requests. Upon successful completion, it has filled the IRP's system
    buffer with a random number. It also sets the IRP's IoStatus.Information
    to the size of the generated number.

Arguments:

    DeviceObject - a pointer to the object that represents the device
        that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/
{
    NTSTATUS            ntStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION  irpStack;
    PUCHAR              outputBuffer;
    ULONG               outputBufferLength;
    BCRYPT_ALG_HANDLE   randomNumberAlgorithm = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Information = 0;

    irpStack = IoGetCurrentIrpStackLocation( Irp );
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if(outputBufferLength == 0)
    {
        ntStatus = STATUS_BUFFER_TOO_SMALL;
        goto Cleanup;
    }

    //
    // Open a handle to  the PRNG algorithm.
    //

    ntStatus = BCryptOpenAlgorithmProvider(
                    &randomNumberAlgorithm,
                    BCRYPT_RNG_ALGORITHM,
                    NULL,
                    0);
    if(!NT_SUCCESS(ntStatus))
    {
        CNGCLIENT_KDPRINT(
            ("ERROR: BCryptOpenAlgorithmProvider returned 0x%x\n",
            ntStatus));

        goto Cleanup;
    }

    //
    // Generate a random number in the output buffer.
    //

    ntStatus = BCryptGenRandom(
                    randomNumberAlgorithm,
                    outputBuffer,
                    outputBufferLength,
                    0);
    if(!NT_SUCCESS(ntStatus))
    {
        CNGCLIENT_KDPRINT(
            ("ERROR: BCryptGenRandom returned 0x%x\n",
            ntStatus));

        goto Cleanup;
    }

    Irp->IoStatus.Information = outputBufferLength;

Cleanup:

    //
    // Close the PRNG algorithm handle
    //

    if (randomNumberAlgorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(randomNumberAlgorithm, 0);
    }

    return ntStatus;
}
///////////////////////////////////////////////////////////////////////////////

