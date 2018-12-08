/*
	2012 vxk,g8,cr4sh,xgtty
*/
#include "stdafx.h"
#include "pagehack.h"
#define NT_DEVICE_NAME L"\\Device\\PageHack"
#define DOS_DEVICE_NAME L"\\DosDevices\\PageHack"
PDRIVER_OBJECT g_DriverObject=NULL;
NTSTATUS
DeviceControl(
			  IN PDEVICE_OBJECT DeviceObject,
			  IN PIRP Irp
			  )
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return STATUS_SUCCESS;
}

NTSTATUS
CreateClose(
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return STATUS_SUCCESS;
}

VOID
DrvUnload(
		  IN PDRIVER_OBJECT DriverObject
		  )
{
	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
	UNICODE_STRING uniWin32NameString;
	NTSTATUS        ntStatus;

	DbgMsg(__FILE__, __LINE__, "DriverUnload()\n");

	RtlInitUnicodeString( &uniWin32NameString, DOS_DEVICE_NAME );

	IoDeleteSymbolicLink( &uniWin32NameString );

	//ntStatus = UnSetupDispatchHandler()

	if ( deviceObject != NULL )
	{
		IoDeleteDevice( deviceObject );
	}

	UnLoadPageHack();

}

NTSTATUS
DriverEntry(
			IN PDRIVER_OBJECT		DriverObject,
			IN PUNICODE_STRING		RegistryPath
			)
{
	NTSTATUS        ntStatus;
	PDEVICE_OBJECT  DeviceObject = NULL;
	UNICODE_STRING  UniDeviceName;
	UNICODE_STRING  UniSymLink;
	g_DriverObject = DriverObject;

	//ntStatus = SetupDispatchHandler();
	DbgInit();
	DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): '%wZ'\n", RegistryPath);  

	RtlInitUnicodeString(&UniDeviceName, NT_DEVICE_NAME);

	ntStatus = IoCreateDevice(
		DriverObject,
		0,
		&UniDeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	RtlInitUnicodeString(&UniSymLink, DOS_DEVICE_NAME);
	ntStatus = IoCreateSymbolicLink(&UniSymLink, &UniDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		DrvUnload(DriverObject);
		return ntStatus;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = 
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = DrvUnload;

	//这里开始尼玛牛B了
	if (!NT_SUCCESS(PageHackTest()))
	{
		DrvUnload(DriverObject);
		return STATUS_UNSUCCESSFUL;
	}
	return ntStatus;
}

