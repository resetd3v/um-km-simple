#pragma once
#include "proc.h"
//#include "pch.h"
//#include "mem.h"


namespace driver {
	// main communication function any deviceio requests from the client are sent to this function
	NTSTATUS DeviceControl(PDEVICE_OBJECT deviceObj, PIRP irp) {
		// not needed so we free
		UNREFERENCED_PARAMETER(deviceObj);
		//DbgPrintEx(0, 0, "[+] DeviceControl: %p\n", irp);
		// default status is unsuccessful until proven otherwise
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		// get the deviceio request
		auto stack = IoGetCurrentIrpStackLocation(irp);
		if (stack == nullptr) { //|| buffer == nullptr || sizeof(*buffer) < sizeof(RW_REQUEST)) {
			DbgPrintEx(0, 0, "[-] invalid params\n");
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(DRIVER_REQUEST)) DbgPrintEx(0, 0, "[-] invalid size\n");
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		static PEPROCESS targProc = nullptr;
		static int targProcID = 0;
		__try {
			// parse the requests buffer as our own defined driver request struct
			PDRIVER_REQUEST request = reinterpret_cast<PDRIVER_REQUEST>(irp->AssociatedIrp.SystemBuffer);
			DbgPrintEx(0, 0, "[+] DRIVER_REQUEST: type=%lu, pid=%lu, address=%p, buffer=%p, size=%zu, returnSize=%zu, base=%p, protect=%lu, size=%zu\n",
				request->type, request->pid, request->address, request->buffer, (SIZE_T)request->size, request->returnSize, request->base, request->protect, sizeof(DRIVER_REQUEST));
			//DbgPrintEx(0, 0, "[+] code: controlCode: %p\n", stack->Parameters.DeviceIoControl.IoControlCode);

			// check the requests opcode/type
			switch (stack->Parameters.DeviceIoControl.IoControlCode) {

			// we now get the target proc in each request instead of saving it in the driver so we can make requests to other processes if needed, not just locked to one
			case cmds::pidCode:
			{
				//auto buffer = reinterpret_cast<PDRIVER_REQUEST>(irp->AssociatedIrp.SystemBuffer);
				//DbgPrintEx(0, 0, "[+] pidCode: pid = %p\n", buffer->pid);
				////buffer->pid = reinterpret_cast<HANDLE>(proc::GetProcID(buffer->procName));
				//status = proc::FindProcessByName(buffer->procName, &targProcID);
				//status = PsLookupProcessByProcessId((HANDLE)targProcID, &targProc);
				break;
			}

			case cmds::baseCode:
			{
				DbgPrintEx(0, 0, "[~] recv base pid: %p", request->pid);
				if (!request->pid) break;

				PEPROCESS process = NULL;
				status = PsLookupProcessByProcessId((HANDLE)request->pid, &process);
				DbgPrintEx(0, 0, "[~] recv base proc: %p", process);
				if (!NT_SUCCESS(status) || !process) {
					DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed with status: %X\n", status);
					break;
				}

				PVOID image_base = PsGetProcessSectionBaseAddress(process);
				DbgPrintEx(0, 0, "[~] recv base base: %p", image_base);
				if (!image_base) {
					ObDereferenceObject(process);
					break;
				}

				//MmCopyVirtualMemory(PsGetCurrentProcess(), image_base, PsGetCurrentProcess(), buffer->base, buffer->size, KernelMode, &buffer->returnSize);
				request->base = image_base;
				status = STATUS_SUCCESS;
				DbgPrintEx(0, 0, "[+] baseCode: proc = %p | b: %p (b: %p | s: %p)\n", request->pid, image_base, request->base, (SIZE_T)request->size);
				ObDereferenceObject(process);
				break;
			}


			case cmds::attachCode:
			{
				//if (targProcID != 0) break;
				//auto buffer = reinterpret_cast<PDRIVER_REQUEST>(irp->AssociatedIrp.SystemBuffer);
				//DbgPrintEx(0, 0, "[+] attachCode: pid = %p\n", buffer->pid);
				////buffer->pid = reinterpret_cast<HANDLE>(proc::GetProcID(buffer->procName));
				////status = proc::FindProcessByName(buffer->procName, &targProc);
				//status = PsLookupProcessByProcessId(buffer->pid, &targProc);
				//DbgPrintEx(0, 0, "[+] attach: stat: %d\n", status);
				break;
			}

			// read mem
			case cmds::readCode:
			{
				//DbgPrintEx(0, 0, "[+] read: targProc = %p\n", buffer->pid);
				// get proc
				PEPROCESS process = NULL;
				status = PsLookupProcessByProcessId((HANDLE)request->pid, &process);
				if (!NT_SUCCESS(status) || !process) {
					DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed with status: %X\n", status);
					break;
				}

				/*PVOID image_base = PsGetProcessSectionBaseAddress(process);
				if (!image_base) return 0;
				ObDereferenceObject(process);*/

				////DbgPrintEx(0, 0, "[+] read: addrValid = %d\n", MmIsAddressValid(buffer->dst));
				//if (!MmIsAddressValid(buffer->dst)) break;
				
				SIZE_T returnSize = 0;
				// copy buffer->size amount of the processes buffer->address to the drivers own process buffer->buffer using cpu priveleged/KernelMode
				MmCopyVirtualMemory(process, request->address, PsGetCurrentProcess(), request->buffer, (SIZE_T)request->size, KernelMode, &returnSize);
				DbgPrintEx(0, 0, "[+] read: addr = %p | buffer = %p\n", request->address, request->buffer);
				request->returnSize = returnSize;
				// not needed, free it
				ObDereferenceObject(process);
				break;
			}

			// write mem
			case cmds::writeCode:
			{
				// get proc
				PEPROCESS process = NULL;
				status = PsLookupProcessByProcessId((HANDLE)request->pid, &process);
				if (!NT_SUCCESS(status) || !process) {
					DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed with status: %X\n", status);
					break;
				}

				//if (!MmIsAddressValid(buffer->dst)) break;
				
				SIZE_T returnSize = 0;
				// copy buffer->size amount of the drivers own process buffer->buffer to process buffer->address using cpu priveleged/KernelMode
				MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer, process, request->address, (SIZE_T)request->size, KernelMode, &returnSize);
				DbgPrintEx(0, 0, "[+] write: addr = %p | buffer = %p\n", request->address, request->buffer);
				request->returnSize = returnSize;
				// not needed, free it
				ObDereferenceObject(process);
				break;
			}

			case cmds::protectMem:
			{
				PEPROCESS process = NULL;
				status = PsLookupProcessByProcessId((HANDLE)request->pid, &process);
				DbgPrintEx(0, 0, "[+] protMem: recv req: pid = %X | proc = %p\n", request->pid, process);
				if (!NT_SUCCESS(status) || !process) {
					DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed with status: %X\n", status);
					break;
				}

				DWORD newProtect = *(DWORD*)request->protect;
				SIZE_T size = (SIZE_T)request->size;

				KeAttachProcess(process);
				status = ZwProtectVirtualMemory(NtCurrentProcess(), &request->address, &size, newProtect, &request->protect);
				KeDetachProcess();

				if (NT_SUCCESS(status)) {
					SIZE_T returnSize = 0;
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &newProtect, PsGetCurrentProcess(), request->buffer, sizeof(newProtect), KernelMode, &returnSize);
					request->returnSize = returnSize;
					DbgPrintEx(0, 0, "[+] protectMem: addr = %p | newProtect = %lu\n", request->address, newProtect);
				}
				else {
					request->returnSize = 0;
					DbgPrintEx(0, 0, "[-] protectMem failed: %X\n", status);
				}

				ObDereferenceObject(process);
				break;
			}

			case cmds::allocMem:
			{
				//DbgPrint(0, 0, "Received protect value: %lu\n", buffer->protect);
				PEPROCESS process = NULL;
				status = PsLookupProcessByProcessId((HANDLE)request->pid, &process);
				DbgPrintEx(0, 0, "[+] allocateMem: recv req: pid = %p | proc = %p\n", request->pid, process);
				if (!NT_SUCCESS(status) || !process) {
					DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed with status: %X\n", status);
					break;
				}

				SIZE_T size = (SIZE_T)request->size;
				if (size == 0) {
					DbgPrintEx(0, 0, "[-] invalid allocation size: %zu\n", size);
					status = STATUS_INVALID_PARAMETER;
					break;
				}
				DbgPrintEx(0, 0, "[+] allocation size: %zu\n", size);

				request->address = NULL;

				/*if (request->protect != PAGE_READWRITE && request->protect != PAGE_EXECUTE_READWRITE) {
					DbgPrintEx(0, 0, "[-] Invalid memory protection flag: %lu\n", request->protect);
					status = STATUS_INVALID_PARAMETER;
					break;
				}*/

				KeAttachProcess(process);
				status = ZwAllocateVirtualMemory(NtCurrentProcess(), &request->address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				KeDetachProcess();

				if (NT_SUCCESS(status)) {
					SIZE_T returnSize = 0;
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &request->address, PsGetCurrentProcess(), request->buffer, sizeof(request->address), KernelMode, &returnSize);
					DbgPrintEx(0, 0, "[+] allocateMem: allocated address = %p | size = %zu\n", &request->address, size);
					request->returnSize = returnSize;
				}
				else {
					DbgPrintEx(0, 0, "[-] allocateMem failed: status = %X\n", status);
				}

				ObDereferenceObject(process);
				break;
			}

			case cmds::freeMem:
			{
				PEPROCESS process = NULL;
				status = PsLookupProcessByProcessId((HANDLE)request->pid, &process);
				DbgPrintEx(0, 0, "[+] freeMem: recv req: pid = %p | proc = %p\n", request->pid, process);
				if (!NT_SUCCESS(status) || !process) {
					DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed with status: %X\n", status);
					break;
				}

				SIZE_T size = 0;

				KeAttachProcess(process);
				status = ZwFreeVirtualMemory(NtCurrentProcess(), &request->address, &size, MEM_RELEASE);
				KeDetachProcess();

				if (NT_SUCCESS(status)) {
					SIZE_T returnSize = 0;
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &request->address, PsGetCurrentProcess(), request->buffer, sizeof(request->address), KernelMode, &returnSize);
					DbgPrintEx(0, 0, "[+] freeMem: freed address = %p | size = %zu\n", request->address, size);
					request->returnSize = returnSize;
				}
				else {
					DbgPrintEx(0, 0, "[-] freeMem failed: status = %X\n", status);
				}

				ObDereferenceObject(process);
				break;
			}


			/*
			case cmds::mouseCode:
			{
				if (targProc == nullptr) return status;
				auto buffer = reinterpret_cast<MOUSE_REQUEST*>(irp->AssociatedIrp.SystemBuffer);

				break;
			}
			*/

			default:
			{
				DbgPrintEx(0, 0, "[-] invalid control code\n");
				status = STATUS_INVALID_DEVICE_REQUEST;
				break;
			}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(0, 0, "[-] UH OH\n");
			status = STATUS_ACCESS_VIOLATION;
		}

		// set the status
		irp->IoStatus.Status = status;
		// set the return size
		irp->IoStatus.Information = sizeof(DRIVER_REQUEST);

		// always have to complete the request, its expecting a response even on a error
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	// can do extra stuff on startup here
	NTSTATUS CreateIO(PDEVICE_OBJECT deviceObj, PIRP irp) {
		UNREFERENCED_PARAMETER(deviceObj);

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}

	// handling closing the deviceio but kdmapper doesnt support unloading drivers
	NTSTATUS CloseIO(PDEVICE_OBJECT deviceObj, PIRP irp) {
		UNREFERENCED_PARAMETER(deviceObj);

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}

	// set every other function to return STATUS_NOT_SUPPORTED
	NTSTATUS UnsupportedIO(PDEVICE_OBJECT deviceObj, PIRP irp) {
		UNREFERENCED_PARAMETER(deviceObj);

		irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}
}
