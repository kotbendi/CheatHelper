#pragma once
#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <string>
//Creator: Kotbendi
class cheat
{
private:
    /* data */
public:
    
    bool WriteToProcessMemory(DWORD pid, DWORD address, const void* data, size_t size) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        if (hProcess == NULL) {
            MessageBoxA(NULL, "Failed to open process.", "Error", MB_OK | MB_ICONERROR);
            return false;
        }
        BOOL result = WriteProcessMemory(hProcess, (LPVOID)address, data, size, NULL);
        CloseHandle(hProcess);
        return result != FALSE;
    }

    int CreatFile(const char* text) {
        
        std::string filename = "file_" + GetCurrentTimeString() + ".txt";
        std::ofstream file(filename);
        file << text;
        file.close();
        MessageBoxA(NULL, ("File created: " + filename).c_str(), "Success", MB_OK);
        return 0;
    }

    
    int CreatFile(const char* name, const char* text) {
        std::ofstream file(name);
        file << text;
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
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess == NULL) {
            std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
            return -1;
        }

        
        void* pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
        if (pLibRemote == NULL) {
            std::cerr << "Failed to allocate memory in remote process. Error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        
        if (!WriteProcessMemory(hProcess, pLibRemote, (void*)dllPath, strlen(dllPath) + 1, NULL)) {
            std::cerr << "Failed to write to process memory. Error: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
            pLibRemote, 0, NULL);
        if (hThread == NULL) {
            MessageBoxA(NULL, "Failed to create remote thread.", "Error", MB_OK | MB_ICONERROR);
            VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE); 
            CloseHandle(hProcess);
            return -1;
        }

        WaitForSingleObject(hThread, INFINITE);

        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return 0;
    }

private:
    
    std::string GetCurrentTimeString() {
        time_t now = time(0);
        tm* localTime = localtime(&now);
        
        char timeStr[100];
        strftime(timeStr, sizeof(timeStr), "%Y%m%d_%H%M%S", localTime);
        
        return std::string(timeStr);
    }

};
