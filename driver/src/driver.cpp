#include "driver.h"
#include <wdmsec.h>


// kdmapper moment (the executable for loading the driver) requires a 2nd entrypoint
NTSTATUS kdmappermoment(PDRIVER_OBJECT driverObj, PUNICODE_STRING regPath) {
	// regpath is not needed so we free it
	UNREFERENCED_PARAMETER(regPath);
	// default status is unsuccessful until proven otherwise
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// init device with pipe name
	UNICODE_STRING deviceName = {};
	RtlInitUnicodeString(&deviceName, L"\\Device\\KISSINGBOYS");
	PDEVICE_OBJECT deviceObj = nullptr;
	status = IoCreateDevice(driverObj, 0, &deviceName, FILE_DEVICE_UNKNOWN,
		0, FALSE, &deviceObj);

	if (status != STATUS_SUCCESS) {
		DbgPrintEx(0, 0, "[-] error device: %p", deviceObj);
		return status;
	}
	DbgPrintEx(0, 0, "[+] DriverDevice: %p\n", deviceObj);


	// init link to usermode through a symbolic link linux!?!?!?!
	UNICODE_STRING symbolicLink = {};
	RtlInitUnicodeString(&symbolicLink, L"\\DosDevices\\KISSINGBOYS");
	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

	if (status != STATUS_SUCCESS) {
		//: %s", symbolicLink
		DbgPrintEx(0, 0, "[-] error symlink\n");
		return status;
	}
	DbgPrintEx(0, 0, "[+] Symlink success\n");

	// improves driver communication speed
	SetFlag(deviceObj->Flags, DO_BUFFERED_IO);
	//set all driver control functions (deviceio) to unsupported
	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		driverObj->MajorFunction[i] = driver::UnsupportedIO;
	
	// redefine the ones that are supported
	driverObj->MajorFunction[IRP_MJ_CREATE] = driver::CreateIO;
	driverObj->MajorFunction[IRP_MJ_CLOSE] = driver::CloseIO;
	driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::DeviceControl;

	// finished init
	ClearFlag(deviceObj->Flags, DO_DEVICE_INITIALIZING);
	DbgPrintEx(0, 0, "[+] driver init success %lu\n", (uintptr_t)driver::DeviceControl);

	return status;
}

// main driver entry
//PDRIVER_OBJECT driverObj, PUNICODE_STRING regPath
NTSTATUS DriverEntry() {
	/*
	UNREFERENCED_PARAMETER(driverObj);
	UNREFERENCED_PARAMETER(regPath);
	*/

	// set the deviceio pipe name
	UNICODE_STRING driverName = {};
	RtlInitUnicodeString(&driverName, L"\\Driver\\KISSINGBOYS");

	// create the pipe and deviceio
	return IoCreateDriver(&driverName, kdmappermoment);
}