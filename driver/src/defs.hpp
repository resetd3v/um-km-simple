#pragma once
#include <ntifs.h>
// =============== not used ===============
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(ntheader) + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + ((ntheader))->FileHeader.SizeOfOptionalHeader))
#define to_lower(text) ((text >= (char*)'A' && text <= (char*)'Z') ? (text + 32) : text)
#define v32(address) ((((unsigned __int64)address^ ((unsigned __int64)address << 13)) >> 7) ^ (unsigned __int64)address^ ((unsigned __int64)address << 13))
#define v33(address) (v32(address) ^ (v32(address) << 17))
#define decrypt_cr3(cr3, key, address) (cr3 & 0xBFFF000000000FFF | (((key ^ v33(address) ^ (v33(address) << 32)) & 0xFFFFFFFFF) << 12))
// windows version specfic offsets
#define win10_1803 17134
#define win10_1809 17763
#define win10_1903 18362
#define win10_1909 18363
#define win10_2004 19041
#define win10_20h2 19042
#define win10_21h1 19043
#define win10_21h2 19044
#define win10_22h2 19045
#define win11_21h2 22000
#define win11_22h2 22621
#define page_offset_size 12
static const uintptr_t pmask = (~0xfull << 8) & 0xfffffffffull;
// =============== not used ===============


// a bunch of undefined windows structs that are used in undocumented ntapi functions - most of these can actually be found in old documented functions
// ====================================================================
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONGLONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Win32VersionValue;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_DOS_HEADER
{
	USHORT e_magic;
	USHORT e_cblp;
	USHORT e_cp;
	USHORT e_crlc;
	USHORT e_cparhdr;
	USHORT e_minalloc;
	USHORT e_maxalloc;
	USHORT e_ss;
	USHORT e_sp;
	USHORT e_csum;
	USHORT e_ip;
	USHORT e_cs;
	USHORT e_lfarlc;
	USHORT e_ovno;
	USHORT e_res[4];
	USHORT e_oemid;
	USHORT e_oeminfo;
	USHORT e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64
{
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR Name[8];
	union {
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;
// ====================================================================

// the actual driver request structure, this info is passed to the driver from the client
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

// not used
typedef struct _MOUSE_REQUEST {
	long x;
	long y;
	unsigned char button_flags;
} MOUSE_REQUEST, * PMOUSE_REQUEST;

// undocumented windows kernel api functions
extern "C" {
	// create the deviceio pipe for communication | https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	// used to read and write memory | https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	// not used but is a very useful function  | https://learn.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation
	NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	// gets the target processes base address | https://doxygen.reactos.org/d2/d9f/ntoskrnl_2ps_2process_8c.html#aec61c9bbcd179ac24285094344e60654
	PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
	// gets a processes information | https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
	NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);

	NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);

	typedef PEPROCESS(*PSGETNEXTPROCESS)(PEPROCESS);
	/*
	EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID               SystemInformation,
		IN ULONG                SystemInformationLength,
		OUT PULONG              ReturnLength OPTIONAL
	);
	*/
}

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