// the most common c com functions known!
#pragma once
#include "pch.h"
#include <psapi.h>

namespace proc {
	// honestly after trying to this from kernel for 4 hours i give up idc if it opens a handle | not used anymore
	// get a processes id from its name
	DWORD GetProcId(LPCTSTR process_name) {
		// current process we are looking for
		PROCESSENTRY32 pe{};
		// takes a snapshot of all processes on the system | https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap == INVALID_HANDLE_VALUE) return 0;

		pe.dwSize = sizeof(PROCESSENTRY32);
		
		// returns if the snapshot list was filled | https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
		if (!Process32First(hSnap, &pe)) {
			CloseHandle(hSnap);
			return 0;
		}

		do {
			// compare the current processes name to the one we are looking for
			if (!lstrcmpi(pe.szExeFile, process_name)) // _wcsicmp
			{
				// found close handle and return the pid
				CloseHandle(hSnap);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnap, &pe));
		// returns the next process in a snapshot | https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next

		// not found
		CloseHandle(hSnap);
		return 0;
	}

	VOID GetProcIdThread(LPCSTR windowClassName, PDWORD procId, PDWORD threadId) {
		*procId = 0;
		while (!*procId) {
			*threadId = GetWindowThreadProcessId(FindWindowA(windowClassName, NULL), procId);
			Sleep(20);
		}
	}

	DWORD threadId = 0;
	DWORD GetWindowThread(DWORD procId) {

		// callback func
		auto EnumWindowsProc = [](HWND hwnd, LPARAM lParam) -> BOOL {
			DWORD winProcId;
			GetWindowThreadProcessId(hwnd, &winProcId);
			if (winProcId == lParam) {
				threadId = GetWindowThreadProcessId(hwnd, nullptr);
				return FALSE;
			}
			return TRUE;
		};
		EnumWindows(EnumWindowsProc, (LPARAM)procId);

		return threadId;
	}

	//HANDLE MapFileToMemory(LPCSTR filename) {
	// // REMOVED DATA
	//}

	// we dont want to save the mapper to disk, if we did it would be alot easier but security
	// this is process hollowing    const std::vector<char>&
	bool ExecutePE(const std::vector<char>& peData) {
		// REMOVED DATA
		return 1;
	}


	std::vector<Proc> getProcesses() {
		std::vector<Proc> processList;

		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE) {
			return processList;
		}

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(hProcessSnap, &pe)) {
			CloseHandle(hProcessSnap);
			return processList;
		}

		do {
			DWORD pid = pe.th32ProcessID;

			std::string processName = utils::wstringToString(pe.szExeFile);

			char filePath[MAX_PATH];
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
			if (hProcess) {
				if (GetModuleFileNameExA(hProcess, NULL, filePath, sizeof(filePath))) {
					std::string checksum = utils::calculateChecksum(filePath);

					//processList.emplace_back(pid, //REMOVED DATA);
					processList.emplace_back(pid);
				}
				CloseHandle(hProcess);
			}
		} while (Process32Next(hProcessSnap, &pe));

		CloseHandle(hProcessSnap);
		return processList;
	}
}