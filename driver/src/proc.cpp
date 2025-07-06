#include "proc.h"

namespace proc {
    // doesnt work cuz win offsets
    NTSTATUS FindProcessByName(IN const char* procName, OUT int* procID) {
        procID = 0;
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        PEPROCESS proc;
        PEPROCESS sysproc = PsInitialSystemProcess;
        PLIST_ENTRY list = (PLIST_ENTRY)((char*)sysproc + ActiveProcessLinks); // _EPROCESS.ActiveProcessLinks
        PLIST_ENTRY head = list;
        do {
            proc = (PEPROCESS)((char*)list - ActiveProcessLinks); // _EPROCESS.ActiveProcessLinks
            if (strstr((char*)proc + ImageFileName, procName)) { // _EPROCESS.ImageFileName
                // changed from (int) cast to int*
                procID = (int*)PsGetProcessId(proc);
                status = STATUS_SUCCESS;
                break;
            }
            list = list->Flink;
        } while (list != head);

        return status;
    }


    uintptr_t GetModuleAddy(int pid, UNICODE_STRING module_name) {

        PEPROCESS proc;
        if (PsLookupProcessByProcessId((HANDLE)pid, &proc) != STATUS_SUCCESS) return 0;

        PPEB p_peb = (PPEB)PsGetProcessPeb(proc);

        if (!p_peb) return 0;

        KAPC_STATE state;

        KeStackAttachProcess(proc, &state);

        PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)p_peb->Ldr;

        if (!pLdr) {
            KeUnstackDetachProcess(&state);
            return 0;
        }


        for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
            list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY)list->Flink)
        {
            PLDR_DATA_TABLE_ENTRY pEntry =
                CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);


            if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == 0) {
                DbgPrintEx(0, 0, "[~] module name: %wZ\n", pEntry->BaseDllName);
                DbgPrintEx(0, 0, "[~] module base: %p\n", pEntry->DllBase);
                DbgPrintEx(0, 0, "[~] module size: %d\n", pEntry->SizeOfImage);
                uintptr_t module_base = (uintptr_t)pEntry->DllBase;
                KeUnstackDetachProcess(&state);

                return module_base;
            }


        }

        KeUnstackDetachProcess(&state);
        DbgPrintEx(0, 0, "[-] failed to find module\n");
        return 0;
    }
}


/*
void* temp;
// last arg probably shouldnt be a nullptr btw
NtQuerySystemInformation(SystemBasicInformation, &temp, sizeof(temp), nullptr);
temp->
*/

// u cant use these in kernel ill see u in 2 hrs when i figure out how to use NtQuerySystemInformation to enumerate through all the proccesses
// timestamp: 1720020884 end (ioctl issue? idk 3hrs new one?): 1720052844
/*

DWORD GetProcID(const CHAR* procName) {
        DWORD procID = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            return procID;
        }

        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (!Process32First(hSnap, &procEntry)) {
            return procID;
        }

        do {
            if (!strcmp(procEntry.szExeFile, procName)) {
                procID = procEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &procEntry));

        CloseHandle(hSnap);
        DbgPrintEx(0, 0, "[+] GetProcID found procID: %lu", procID);
        return procID;
    }

    uintptr_t GetModuleBaseAddress(DWORD procID, const TCHAR* modName) {
        DWORD modBaseAddr = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);
        if (hSnap == INVALID_HANDLE_VALUE) {
            //LOGGER::printError(TEXT("failed CreateToolhelp32Snapshot"));
            return modBaseAddr;
        }

        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);

        if (!Module32First(hSnap, &modEntry)) {
            //LOGGER::printError(TEXT("failed Process32First"));
            return modBaseAddr;
        }

        do {
            if (!strcmp(modEntry.szModule, modName)) {
                modBaseAddr = (uintptr_t) modEntry.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnap, &modEntry));

        CloseHandle(hSnap);
        DbgPrintEx(0, 0, "[+] GetModuleBaseAddress found addr: %lu", modBaseAddr);
        return modBaseAddr;
    }

*/