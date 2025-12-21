#pragma once
#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <TlHelp32.h>
#include <shellapi.h>
#include <string>
//Creator: Kotbendi
class cheat
{
private:
    /* data */
public:
    
    bool WriteToProcessMemory(DWORD pid, DWORD_PTR address, const void* data, size_t size) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        if (hProcess == NULL) {
            MessageBoxA(NULL, "Failed to open process.", "Error", MB_OK | MB_ICONERROR);
            return false;
        }
        BOOL result = WriteProcessMemory(hProcess, (LPVOID)address, data, size, NULL);
        CloseHandle(hProcess);
        return result != FALSE;
    }


    int CreatFile(const char* name, const char* text) {
        std::ofstream file(name);
        file << text;
        file.close();
        return 0;
    }
    int ReadFile(const char* name, char* buffer, size_t bufferSize) {
        std::ifstream file(name);
        if (!file.is_open()) {
            return -1;
        }
        file.read(buffer, bufferSize - 1);
        buffer[file.gcount()] = '\0';
        file.close();
        return 0;
	}

    bool IsRunningAsAdmin() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;

        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
                isAdmin = FALSE;
            }
            FreeSid(adminGroup);
        }
        return isAdmin == TRUE;
    }

    int GetAdmin() {
        if (IsRunningAsAdmin()) {
            return 0;
        }
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);

        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = path;
        sei.lpParameters = "";
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        if (ShellExecuteExA(&sei)) {
            return 0;
        }
        else {
            MessageBoxA(NULL, "Failed to gain admin rights.", "Error", MB_OK | MB_ICONERROR);
            return -1;
        }
    }
        int LoadedDLL(const char* dllPath, const int pid) {
        HANDLE hProcess = OpenProcess(
            PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ,
            FALSE,
            pid
        );

        if (!hProcess) {
            std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
            return -1;
        }

        
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) {
            std::cerr << "GetModuleHandle failed. Error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        LPTHREAD_START_ROUTINE pLoadLibrary =
            (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

        if (!pLoadLibrary) {
            std::cerr << "GetProcAddress failed. Error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        
        SIZE_T pathLen = strlen(dllPath) + 1;

        void* pLibRemote = VirtualAllocEx(
            hProcess,
            nullptr,
            pathLen,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!pLibRemote) {
            std::cerr << "VirtualAllocEx failed. Error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        
        if (!WriteProcessMemory(
            hProcess,
            pLibRemote,
            dllPath,
            pathLen,
            nullptr
        )) {
            std::cerr << "WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }

        
        HANDLE hThread = CreateRemoteThread(
            hProcess,
            nullptr,
            0,
            pLoadLibrary,
            pLibRemote,
            0,
            nullptr
        );

        if (!hThread) {
            std::cerr << "CreateRemoteThread failed. Error: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }

        
        WaitForSingleObject(hThread, INFINITE);

        
        DWORD exitCode = 0;
        if (!GetExitCodeThread(hThread, &exitCode) || exitCode == 0) {
            std::cerr << "LoadLibrary failed inside target process." << std::endl;
        }

        
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return exitCode != 0 ? 0 : -1;
        return 0;
    }

};



