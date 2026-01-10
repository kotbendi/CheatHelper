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
    
    
    ch.CreateConsole("YourConsoleTitle"); //Create Console
    
    std::vector<unsigned int> offset = { 0x11 }; //Your offsets here
    
    ch.FileExists("path to file"); // return true or false
    
    ch.FindWindowByTitle("notepad.exe"); //Find Window by title return true or false
    
	ch.MemoryChain(hproc, &ptr, offset); 

    ch.ReadPtr(Write handle here, 0x12345678);
	
    int value = ch.ReadMemory<int>(Write handle here, 0x111); 
	
	ch.ReadBytes(Write handle here, 0x12345678, 0, 16);
	
    ch.WriteMemory<int>(Write handle here, 0x111, value); 

    return 0;

}
//More Soon...







