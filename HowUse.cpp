#include "CheatHelper.hpp"

int main(){
    cheat ch;

    ch.LoadedDLL("Path to dll","Process ID/PID");

    ch.CreatFile("test.txt","Test text");

    int result = ch.GetAdmin();

    if (result == 1){
        // user accept admin rights
    }
    else{
        //user dont accept admin rights
    }
        uintptr_t base = ch.GetModuleBaseAddress(PID, L"test.dll"); //GetModuleBaseAddress
    
        printf("Memory info:\n"); //get memory info
        printf("BaseAddress      : %p\n", mbi.BaseAddress);
        printf("AllocationBase   : %p\n", mbi.AllocationBase);
        printf("RegionSize       : %zu bytes\n", mbi.RegionSize);
        printf("State            : 0x%X\n", mbi.State);
        printf("Protect          : 0x%X\n", mbi.Protect);
        printf("AllocProtect     : 0x%X\n", mbi.AllocationProtect);
        printf("Type             : 0x%X\n", mbi.Type);
    
    
    ch.WriteToProcessMemory(TargetPID,MemoryAddress, &newValue,sizeof(int))

    return 0;

}
//More Soon...

