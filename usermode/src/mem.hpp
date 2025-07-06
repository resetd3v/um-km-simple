// most of this is stolen cuz at the time i didnt have time to learn windows internals :( which is why they look so different and better
#pragma once
#include "pch.h"

#pragma comment(lib, "ntdll.lib")

namespace mem {
	// https://github.com/KANKOSHEV/face-injector-v2/blob/main/face_injector_v2/inject/injector.h#L148  |  i dont have enough time to learn this much windows internals so im breaking one my own rules

	// im sure this exact function is in 50 different places same can be said for the next 7 functions, they are generic helper functions for manual mapping
	// this function turns the address of the dll from disk into real memory addresses (basically)
	PVOID RVA_VA(ULONGLONG RVA, PIMAGE_NT_HEADERS NtHead, PVOID LocalImage) {
		PIMAGE_SECTION_HEADER pFirstSect = IMAGE_FIRST_SECTION(NtHead);
		// loop through sections
		for (PIMAGE_SECTION_HEADER pSection = pFirstSect; pSection < pFirstSect + NtHead->FileHeader.NumberOfSections; pSection++)
			if (RVA >= pSection->VirtualAddress && RVA < pSection->VirtualAddress + pSection->Misc.VirtualSize)
				return (PUCHAR)LocalImage + pSection->PointerToRawData + (RVA - pSection->VirtualAddress);

		return NULL;
	}

	// gets the offset of a dlls function from the start of said dll
	ULONGLONG ResolveFunctionAddress(LPCSTR ModName, LPCSTR ModFunc) {
		HMODULE hModule = LoadLibraryExA(ModName, NULL, DONT_RESOLVE_DLL_REFERENCES);
		ULONGLONG FuncOffset = (ULONGLONG)GetProcAddress(hModule, ModFunc);
		FuncOffset -= (ULONGLONG)hModule;
		FreeLibrary(hModule);

		return FuncOffset;
	}

	// this is a very very common function in reversing to fix iat
	// dlls also have more dlls (imports) this fixes the iat (import address table) from the relocation the manual mapping does
	BOOL ResolveImport(PVOID pLocalImg, PIMAGE_NT_HEADERS NtHead) {
		PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)RVA_VA(NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, NtHead, pLocalImg);
		if (!NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) \
			return TRUE;

		LPSTR ModuleName = NULL;
		// loop through imports
		while ((ModuleName = (LPSTR)RVA_VA(ImportDesc->Name, NtHead, pLocalImg))) {
			// load the import
			uintptr_t BaseImage = (uintptr_t)LoadLibraryA(ModuleName);

			if (!BaseImage)
				return FALSE;

			// load the metadata about the import
			PIMAGE_THUNK_DATA IhData = (PIMAGE_THUNK_DATA)RVA_VA(ImportDesc->FirstThunk, NtHead, pLocalImg);
			// loop through metadata
			while (IhData->u1.AddressOfData) {
				// fix function pointers because of the relocation
				if (IhData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					IhData->u1.Function = BaseImage + ResolveFunctionAddress(ModuleName, (LPCSTR)(IhData->u1.Ordinal & 0xFFFF));
				else {
					IMAGE_IMPORT_BY_NAME* IBN = (PIMAGE_IMPORT_BY_NAME)RVA_VA(IhData->u1.AddressOfData, NtHead, pLocalImg);
					IhData->u1.Function = BaseImage + ResolveFunctionAddress(ModuleName, (LPCSTR)IBN->Name);
				} IhData++;
			} ImportDesc++;
		} return true;
	}

	// in the name, write the dlls sections to the target address space
	VOID WriteSections(DWORD ProcessId, PVOID pModuleBase, PVOID LocalImage, PIMAGE_NT_HEADERS NtHead) {
		PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHead);
		for (WORD SectionCount = 0; SectionCount < NtHead->FileHeader.NumberOfSections; SectionCount++, Section++) {
			// write the address of start of each sections to the dlls actual memory
			NTSTATUS WriteStatus = driver.write((PVOID)((ULONGLONG)pModuleBase + Section->VirtualAddress), (PVOID)((ULONGLONG)LocalImage + Section->PointerToRawData), Section->SizeOfRawData);
		}
	}

	// some sections arent needed, fill those with zeros
	VOID EraseDiscardableSect(DWORD ProcessId, PVOID pModuleBase, PIMAGE_NT_HEADERS NtHead) {
		PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHead);
		// loop through sections
		for (WORD SectionCount = 0; SectionCount < NtHead->FileHeader.NumberOfSections; SectionCount++, Section++) {
			if (Section->SizeOfRawData == 0)
				continue;

			// if the section is "discardable"
			if (Section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
				// prepare a buffer of 00 bytes for the size of the section
				PVOID pZeroMemory = VirtualAlloc(NULL, Section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				// write that buffer to the dll
				driver.write((PVOID)((ULONGLONG)pModuleBase + Section->VirtualAddress), pZeroMemory, Section->SizeOfRawData);
				// free the buffer
				VirtualFree(pZeroMemory, 0, MEM_RELEASE);
			}
		}
	}

	// voodoo magic to shift/relocate the image and fix its headers to the new address space | loading a dll normally is fine, the headers will be correct. manually mapping means these headers need to be adjusted to fit the new address space i think
	BOOL RelocateImage(PVOID pRemoteImg, PVOID pLocalImg, PIMAGE_NT_HEADERS NtHead) {
		typedef struct _RELOC_ENTRY {
			ULONG ToRVA;
			ULONG Size;
			struct
			{
				WORD Offset : 12;
				WORD Type : 4;
			} Item[1];
		} RELOC_ENTRY, * PRELOC_ENTRY;

		ULONGLONG DeltaOffset = (ULONGLONG)pRemoteImg - NtHead->OptionalHeader.ImageBase;
		if (!DeltaOffset)
			return TRUE;
		else if (!(NtHead->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
			return FALSE;

		PRELOC_ENTRY RelocEnt = (PRELOC_ENTRY)RVA_VA(NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, NtHead, pLocalImg);
		ULONGLONG RelocEnd = (ULONGLONG)RelocEnt + NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if (RelocEnt == nullptr)
			return TRUE;

		while ((uintptr_t)RelocEnt < RelocEnd && RelocEnt->Size) {
			DWORD RecordsCount = (RelocEnt->Size - 8) >> 1;
			for (DWORD i = 0; i < RecordsCount; i++) {
				WORD FixType = (RelocEnt->Item[i].Type);
				WORD ShiftDelta = (RelocEnt->Item[i].Offset) % 4096;

				if (FixType == IMAGE_REL_BASED_ABSOLUTE)
					continue;

				if (FixType == IMAGE_REL_BASED_HIGHLOW || FixType == IMAGE_REL_BASED_DIR64) {
					uintptr_t FixVA = (uintptr_t)RVA_VA(RelocEnt->ToRVA, NtHead, pLocalImg);

					if (!FixVA)
						FixVA = (uintptr_t)pLocalImg;

					*(uintptr_t*)(FixVA + ShiftDelta) += DeltaOffset;
				}
			}

			RelocEnt = (PRELOC_ENTRY)((LPBYTE)RelocEnt + RelocEnt->Size);
		}
		return TRUE;
	}

	BYTE RemoteCallDllMain[92] = {
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
	0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
	0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
	0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
	}; DWORD ShellDataOffset = 0x6;

	typedef struct _MAIN_STRUCT {
		INT Status;
		uintptr_t FnDllMain;
		HINSTANCE DllBase;
	} MAIN_STRUCT, * PMAIN_STRUCT;

	// this is to call the dllmain
	BOOL CallViaSetWindowsHookEx(DWORD ProcessId, DWORD ThreadId, PVOID DllBase, PIMAGE_NT_HEADERS NtHeader) {
		HMODULE NtDll = LoadLibraryW(L"ntdll.dll");

		PVOID AllocShellCode = NULL;
		driver.alloc(&AllocShellCode, 0x1000, PAGE_EXECUTE_READWRITE);

		DWORD ShellSize = sizeof(RemoteCallDllMain) + sizeof(MAIN_STRUCT);
		PVOID AllocLocal = VirtualAlloc(NULL, ShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		RtlCopyMemory(AllocLocal, &RemoteCallDllMain, sizeof(RemoteCallDllMain));
		ULONGLONG ShellData = (ULONGLONG)AllocShellCode + sizeof(RemoteCallDllMain);
		*(ULONGLONG*)((ULONGLONG)AllocLocal + ShellDataOffset) = ShellData;

		PMAIN_STRUCT MainData = (PMAIN_STRUCT)((ULONGLONG)AllocLocal + sizeof(RemoteCallDllMain));
		MainData->DllBase = (HINSTANCE)DllBase;
		MainData->FnDllMain = ((ULONGLONG)DllBase + NtHeader->OptionalHeader.AddressOfEntryPoint);
		driver.write(AllocShellCode, AllocLocal, ShellSize);

		HHOOK hHook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)AllocShellCode, NtDll, ThreadId);
		while (MainData->Status != 2) {
			PostThreadMessage(ThreadId, WM_NULL, 0, 0);
			Sleep(10);
			driver.read((PVOID)ShellData, (PVOID)MainData, sizeof(MAIN_STRUCT));
		}
		UnhookWindowsHookEx(hHook);

		BYTE ZeroShell[116ui64] = { 0 };
		driver.write(AllocShellCode, ZeroShell, 116ui64);

		driver.free(AllocShellCode);
		VirtualFree(AllocLocal, 0, MEM_RELEASE);

		return TRUE;
	}

	VOID Map(ULONG threadId, std::vector<BYTE> dllBytes) {
		// load the dll in our local memory so we can read stuff we need
		PVOID dllImage = VirtualAlloc(nullptr, dllBytes.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!dllImage) {
			printf("failed to alloc memory for dll | %p\n", GetLastError());
			return;
		}
		memcpy(dllImage, dllBytes.data(), dllBytes.size());

		// get the headers
		PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(dllImage);
		if (!ntHeaders) {
			printf("invalid pe headers | %p\n", GetLastError());
			return;
		}

		// allocate, using the driver, memory for the dll to be loaded into
		PVOID allocBase = NULL;
		driver.alloc(&allocBase, ntHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);

		if (!allocBase) {
			printf("failed alloc");
			return;
		}

		ULONG DllSize = ntHeaders->OptionalHeader.SizeOfImage;
		ULONG DllEntryPointOffset = ntHeaders->OptionalHeader.AddressOfEntryPoint;

		// explained at the function def
		if (!RelocateImage(allocBase, dllImage, ntHeaders)) {
			driver.free(allocBase);
			printf("failed to relocate image | %p\n", GetLastError());
			return;
		}

		// explained at the function def
		if (!ResolveImport(dllImage, ntHeaders)) {
			driver.free(allocBase);
			printf("failed to resolve imports | %p\n", GetLastError());
			return;
		}

		// explained at the function def
		WriteSections(driver.processId, allocBase, dllImage, ntHeaders);
		// explained at the function def
		EraseDiscardableSect(driver.processId, allocBase, ntHeaders);

		printf("wrote DLL to process %i at address %p\n", driver.processId, allocBase);

		// explained at the function def | finally call the loaded dll
		CallViaSetWindowsHookEx(driver.processId, threadId, allocBase, ntHeaders);

		// free the memory of the dll we loaded in our local memory for manipulation
		VirtualFree(dllImage, 0, MEM_RELEASE);
	}
}