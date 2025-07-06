#pragma once

//#include "com.hpp"
//#include <iostream>
#include <TlHelp32.h>
//#include <Windows.h>


#include "proc.hpp"
//#include "settings.hpp"

// opcode for each type of operation
#define CMD_ATTACH 0x42013
#define CMD_BASE 0x42018
#define CMD_PID 0x42014
#define CMD_READ 0x42015
#define CMD_WRITE 0x42016
#define CMD_MOUSE 0x42017
#define PROT_MEM 0x42019
#define ALLOC_MEM 0x42020
#define FREE_MEM 0x42021

// turning opcodes into deviceio codes
namespace cmds {
	constexpr ULONG attachCode = CTL_CODE(FILE_DEVICE_UNKNOWN, CMD_ATTACH, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	constexpr ULONG baseCode = CTL_CODE(FILE_DEVICE_UNKNOWN, CMD_BASE, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	constexpr ULONG pidCode = CTL_CODE(FILE_DEVICE_UNKNOWN, CMD_PID, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	constexpr ULONG readCode = CTL_CODE(FILE_DEVICE_UNKNOWN, CMD_READ, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	constexpr ULONG writeCode = CTL_CODE(FILE_DEVICE_UNKNOWN, CMD_WRITE, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	constexpr ULONG mouseCode = CTL_CODE(FILE_DEVICE_UNKNOWN, CMD_MOUSE, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	constexpr ULONG protectMem = CTL_CODE(FILE_DEVICE_UNKNOWN, PROT_MEM, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	constexpr ULONG allocMem = CTL_CODE(FILE_DEVICE_UNKNOWN, ALLOC_MEM, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	constexpr ULONG freeMem = CTL_CODE(FILE_DEVICE_UNKNOWN, FREE_MEM, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
}



class _driver
{
private:


	// not needed
	typedef __int64(*NtUserFunction)(uintptr_t);
	NtUserFunction nt_user_function = 0;

	// the actual driver request structure, this info is passed to the driver
	typedef struct _DRIVER_REQUEST {
		ULONG type;				// tells the driver what type of operation (opcode)
		ULONG pid;				// the process id of the target process
		PVOID address;			// the address to read/write to
		PVOID buffer;			// buffer for the driver response | read - driver fills with data from the target address, write - client fills and driver reads data to write to the target address
		SIZE_T size;			// size of buffer
		SIZE_T returnSize;		// response size
		PVOID base;				// base address of the process
		DWORD protect;			// protection for address space being modified
	} DRIVER_REQUEST, * PDRIVER_REQUEST;

	// final function to send the actual request using DeviceIoControl to the driver
	bool SendRequest(PDRIVER_REQUEST out) {
		//printf("size of driver struct: %zu\n", sizeof(DRIVER_REQUEST));
		printf("DRIVER_REQUEST: type=%lu, pid=%lu, address=%p, buffer=%p, size=%zu, protect=%lu, size=%zu\n",
			out->type, out->pid, out->address, out->buffer, out->size, out->protect, sizeof(DRIVER_REQUEST));
		//RtlSecureZeroMemory(out, 0);
		DWORD bytesReturned = 0;
		bool result = DeviceIoControl(driver_handle, out->type, out, sizeof(DRIVER_REQUEST), out, sizeof(DRIVER_REQUEST), &bytesReturned, nullptr);
		if (!result) {
			DWORD dwError = GetLastError();
			//printf("%p error: %p\n", out->type, dwError);
			printf("DeviceIoControl failed: %lu\n", dwError);
		}
		return result;
		//nt_user_function(reinterpret_cast<uintptr_t>(out));
	}

	// initialise driver
	bool init() {
		NTSTATUS status = false;
		// connect to driver
		status = GetDriverHandle();
		//status &= GetDriverHandle();
		//if (!GetDriverHandle()) return false;
		return status;
	}

	// load driver
	bool MapDriver(std::vector<char> respBuffer) {
		//HANDLE image = proc::MapFileToMemory("C:\\Windows\\notepad.exe");
		proc::ExecutePE(respBuffer);

		return 0;
	}

	// connect to driver
	bool GetDriverHandle() {
		driver_handle = CreateFile(L"\\\\.\\KISSINGBOYS", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		//std::cout << "DriverHandle " << driverHandle << std::endl;
		return driver_handle != INVALID_HANDLE_VALUE;
	}

public:
	std::string mapperResp;
	std::string driverResp;
	std::vector<char> mapperBuf;
	std::vector<char> driverBuf;

	HANDLE driver_handle;
	ULONG processId;
	ULONG threadId;
	uintptr_t baseAddress;

	// setup driver
	bool setup() {
		//// download mapper
		//mapperBuf = comm.GetMapper();
		//printf("%s\n", mapperResp.c_str());
		//if (mapperBuf.empty()) return false;
		//// download driver
		///*driverBuf = comm.GetDriver();
		//if (driverBuf.empty()) return false;*/
		//
		//// load driver
		//if (!MapDriver(mapperBuf)) return false;

		return this->init();
	}

	// gets the base address of a process
	uintptr_t GetBaseAddr() {
		DRIVER_REQUEST out{};
		out.type = cmds::baseCode;
		out.pid = processId;
		out.size = sizeof(uintptr_t);
		SendRequest(&out);
		uintptr_t baseAddress = (uintptr_t)out.base;
		return baseAddress;
	}

	// write memory
	bool write(PVOID address, PVOID buffer, DWORD size) {
		DRIVER_REQUEST out{};
		out.type = cmds::writeCode;
		out.pid = processId;
		out.address = address;
		out.buffer = buffer;
		out.size = size;
		return SendRequest(&out);
	}

	// read memory
	bool read(PVOID address, PVOID buffer, DWORD size) {
		DRIVER_REQUEST out{};
		out.type = cmds::readCode;
		out.pid = processId;
		out.address = address;
		out.buffer = buffer;
		out.size = size;
		return SendRequest(&out);
	}

	// alloc memory
	bool alloc(PVOID buffer, SIZE_T size, DWORD protect) {
		DRIVER_REQUEST out{};
		out.type = cmds::allocMem;
		out.pid = processId;
		out.address = 0;
		out.buffer = buffer;
		out.size = size;
		out.protect = protect;
		return SendRequest(&out);
	}

	// free memory
	bool free(PVOID address) {
		DRIVER_REQUEST out{};
		out.type = cmds::freeMem;
		out.pid = processId;
		out.address = address;
		return SendRequest(&out);
	}

	// ik these pvoid casts are weird i just prefered it for sum reason i think i dont remember at all
	
	// write memory wrapper
	template<typename T> void write(uintptr_t address, T value, bool safe_mode) {
		if (safe_mode) return;
		write((PVOID)address, &value, sizeof(T));
	}

	// read memory wrapper
	template<typename T> T read(uintptr_t address) {
		// this is the same as allocating a buffer
		T buffer{};
		read((PVOID)address, &buffer, sizeof(T));
		return buffer;
	}

	// read memory wrapper for raw bytes
	void read(uintptr_t address, void* buffer, size_t size) {
		read((PVOID)address, buffer, size);
	}

};

// init class
_driver driver;