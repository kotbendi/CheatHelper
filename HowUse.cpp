#include "CheatHelper.hpp"

int main(){
    cheat cheat1;

    cheat1.LoadedDLL("Path to dll","Process ID/PID");

    cheat1.CreatFile("test.txt","Test text");

    int result = cheat1.GetAdmin();

    if (result == 1){
        // user accept admin rights
    }
    else{
        //user dont accept admin rights
    }
    
    cheat1.WriteToProcessMemory(TargetPID,MemoryAddress, &newValue,sizeof(int))

    return 0;
}