#pragma once
#include "pch.h"

// undocumented windows kernel api functions
namespace proc {
	NTSTATUS FindProcessByName(const CHAR* process_name, int* procID);
	//NTSTATUS FindProcessByName(const CHAR* process_name, PEPROCESS* process);
	uintptr_t GetModuleBaseAddress(DWORD procID, const TCHAR* modName);
}

/*
// can use | nvm
#include <TlHelp32.h>
#include <handleapi.h>
// cant use in kernel
//#include <windows.h>
*/

// a bunch of undefined windows structs that are used in undocumented ntapi functions - most of these can actually be found in old documented functions
typedef enum _EPROCESS_OFFSETS {

    ActiveProcessLinks = 0x448,
    UniqueProcessId = 0x2e8,
    ImageFileName = 0x5a8
} EPROCESS_OFFSETS;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

/*
NTSYSCALLAPI
__declspec(dllimport) PPEB PsGetProcessPeb(PEPROCESS);
*/