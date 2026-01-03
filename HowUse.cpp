#include "CheatHelper.hpp"

int main(){
    cheat ch;

    ch.LoadedDLL("Path to dll","Process ID/PID");//Inject dll

    ch.CreatFile("test.txt","Test text");

    int result = ch.GetAdmin();

    if (result == 1){
        // user accept admin rights
    }
    else{
        //user dont accept admin rights
    }
    DWORD PID = ch.FindProcessId(L"notepad.exe");//Find PID
    
    uintptr_t base = ch.GetModuleBaseAddress(PID, L"test.dll"); //GetModuleBaseAddress
    
    ch.DownloadFile("https://github.com/kotbendi/SimplGuiInjectorDll/releases/download/v1.0/Injector.rar", "lexa.rar"); //download file
    
    printf("Memory info:\n"); //get memory info
    printf("BaseAddress      : %p\n", mbi.BaseAddress);
    printf("AllocationBase   : %p\n", mbi.AllocationBase);
    printf("RegionSize       : %zu bytes\n", mbi.RegionSize);
    printf("State            : 0x%X\n", mbi.State);
    printf("Protect          : 0x%X\n", mbi.Protect);
    printf("AllocProtect     : 0x%X\n", mbi.AllocationProtect);
    printf("Type             : 0x%X\n", mbi.Type);
    
    std::string path = ch.GetMainFilePath();//Find path to main program
    
    ch.CreateConsole("YourConsoleTitle"); //Create Console
    
    std::vector<unsigned int> offset = { 0x11 }; //Your offsets here
    
    ch.FileExists("path to file"); // return true or false
    
    ch.FindWindowByTitle("notepad.exe"); //Find Window by title return true or false
    
	ch.FindDMAAddy(hproc, &ptr, offset); 
    
    ch.WriteToProcessMemory(TargetPID,MemoryAddress, &newValue,sizeof(int));//Write to process memory

    return 0;

}
//More Soon...




