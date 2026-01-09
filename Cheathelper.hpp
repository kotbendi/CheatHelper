#pragma once
#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <TlHelp32.h>
#include <shellapi.h>
#include <string>
#include <filesystem>
#include <direct.h>
#include <urlmon.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib") 
#pragma comment(lib, "urlmon.lib")
//Creator: Kotbendi
class cheat
{
private:
    /* data */
public:
    uintptr_t GetModuleBaseAddress(DWORD pid, const wchar_t* moduleName)
    {
        uintptr_t baseAddress = 0;

        HANDLE snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid
        );

        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        MODULEENTRY32W module;
        module.dwSize = sizeof(module);

        if (Module32FirstW(snapshot, &module))
        {
            do
            {
                if (!_wcsicmp(module.szModule, moduleName))
                {
                    baseAddress = (uintptr_t)module.modBaseAddr;
                    break;
                }
            } while (Module32NextW(snapshot, &module));
        }

        CloseHandle(snapshot);
        return baseAddress;
    }
    DWORD FindProcessId(const std::wstring& processName)
    {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(PROCESSENTRY32W);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (processName == entry.szExeFile)
                {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return 0;
    }
    bool CreateConsole(const char* Title = "Console")
    {
        
        if (!AllocConsole())
            return false;

        SetConsoleTitleA(Title);
        FILE* fp;

        freopen_s(&fp, "CONOUT$", "w", stdout); 
        freopen_s(&fp, "CONIN$", "r", stdin);   
        freopen_s(&fp, "CONOUT$", "w", stderr); 


        std::ios::sync_with_stdio();
        return true;
        
    }
    template<typename T> T ReadMemory(HANDLE hProc, uintptr_t Addres) {
		if (!hProc) {
			std::perror("Invalid process handle"); //error
            return T();
        }
        T buffer
        ReadProcessMemory(hProc, (LPCVOID)Addres, &buffer, sizeof(T), nullptr);
        return buffer;
    };
    template<typename T> bool WriteMemory(HANDLE hProc, uintptr_t Addres, T value) {
        if (!hProc) {
			return false; //error
        }
		return WriteProcessMemory(hProc, (LPVOID)Addres, &value, sizeof(T), nullptr);
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
    bool DownloadFile(const char* Url, const char* Name) {
        HRESULT hr = URLDownloadToFileA(
            NULL,
            Url,
            Name,
            0,
            NULL
        );
        
        if (hr == S_OK)
            return true;
        else
            return false;

    }
    bool isConnectedToInternet() {
        if (InternetCheckConnection(L"http://www.google.com", FLAG_ICC_FORCE_CONNECTION, 0)) {
            return true;
        }
        else {
            return false;
        }
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
    int DeleteFile(const char* path) {

        if (std::remove(path) == 0) {
            //deleted successful
            return 0;
        }
        else {
            //deleted fail!
            return 1;
        }
    }
    std::string GetMainFilePath() {
        char path[260];
        _getcwd(path, sizeof(path));
        return path;
    }
    uintptr_t MemmoryChain(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets) {
        uintptr_t addr = ptr;
        for (unsigned int i = 0; i < offsets.size(); i++) {
            ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
            addr += offsets[i];
        }
        return addr;
    }
    bool FileExists(const std::string& path)
    {
        return std::filesystem::exists(path);
    }
    uintptr_t ReadPtr(HANDLE hProcess, uintptr_t address)
    {
        uintptr_t ptr = 0;
        ReadProcessMemory(hProcess, (LPCVOID)address, &ptr, sizeof(ptr), nullptr);
        return ptr;
    }
    std::vector<uint8_t> ReadBytes(HANDLE hProсess, uintptr_t adress, int offset, size_t bytes) {
        std::vector<uint8_t> buffer(bytes);
		ReadProcessMemory(hProсess, (LPCVOID)(adress + offset), buffer.data(), bytes, nullptr);
		return buffer;
    }
    bool FindWindowByTitle(const char* WindowName) {
        HWND hwnd = FindWindowA(0,WindowName);
        if (!hwnd) {
            std::perror("Window not found");
            return false;
        }
        else {
            return true;
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
