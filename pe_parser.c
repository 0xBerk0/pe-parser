#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <DbgHelp.h>
#pragma comment(lib, "Imagehlp.lib")

int Error(char *msg) {
    printf("[-] %s : %d\n", msg, GetLastError());
    return 1;
}

int main (int argc, char *argv[]) {

    if (argc != 2){
        printf("[!] Usage: pe_analyzer.exe <executable to be analyze>\n");
        return 1;
    }

    // Open the executable we want to analyze  and get an handle to it
    HANDLE hFile = CreateFileA(
        argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (hFile == INVALID_HANDLE_VALUE){
        return Error("Failed to open file");
    }

    // obtain the size of the target executable in order to know how much memory to allocate within our current process
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == 0) {
        printf("[!] Target executable is empty\n");
        return 1;
    }

    // Allocate memory within current process in order to store the data from the target executable
    void *lpFileBuffer = VirtualAlloc(NULL, dwFileSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (!lpFileBuffer){
        CloseHandle(hFile);
        return Error("VirtualAlloc failed");
    }

    // used to know if the size of the file matches with read data size
    DWORD lpNumberOfBytesRead = 0;

    // Read executable's data and store it in the lpFileBuffer 
    if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &lpNumberOfBytesRead, NULL)){
        VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return Error("Failed to read executable data\n");
    }

    if (lpNumberOfBytesRead != dwFileSize){
        VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        printf("[-] Number of read bytes doesn't match file size\n");
        return 1;
    }

    // now that we have executable's data stored in the lpFileBuffer
    // we no longer need an handle to the file
    CloseHandle(hFile);

    // Cast that will allow to validate if the file is a valid PE, since the 
    // first two bytes, e_magic,  from a PE are 4D5A, in ASCII "MZ"
    PIMAGE_DOS_HEADER pImageDOSHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;

    // now we can validate if the file is a valid PE
    if (pImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE){
        printf("[!] Please use a valid executable\n");
        return 1;
    }

    // obtaining NT Headers location , or also called PE Headers, is pretty simply
    // since in the DOS Header we have the e_lfanew, the last number of the DOS Header located at offset 0x3C
    // that contains the offset to the start of the NT Headers
    IMAGE_DATA_DIRECTORY imageExportDataDirectory = {0};
    PIMAGE_NT_HEADERS pImageNTHeaders = (PIMAGE_NT_HEADERS)((BYTE *)pImageDOSHeader + pImageDOSHeader->e_lfanew);
    if (pImageNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC){
        PIMAGE_NT_HEADERS64 pImageNTHeaders64 = (PIMAGE_NT_HEADERS64)pImageNTHeaders;
        imageExportDataDirectory =  pImageNTHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }else if(pImageNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC){
        PIMAGE_NT_HEADERS32 pImageNTHeaders32 = (PIMAGE_NT_HEADERS32)pImageNTHeaders;
        imageExportDataDirectory =  pImageNTHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    printf("| MAGIC NUMBER          : 0x%04X\n", pImageDOSHeader->e_magic);
    printf("| E_LFANEW              : 0x%08X\n", pImageDOSHeader->e_lfanew);
    printf("| NT HEADERS LOCATION   : 0x%p\n",   (void*)pImageNTHeaders);
    printf("| NT HEADERS SIGNATURE  : 0x%08X\n", pImageNTHeaders->Signature);

    printf("| MACHINE               : 0x%04X\n", pImageNTHeaders->FileHeader.Machine);
    printf("| NUMBER OF SECTIONS    : %d\n",     pImageNTHeaders->FileHeader.NumberOfSections);
    printf("| TIMESTAMP             : 0x%08X\n", pImageNTHeaders->FileHeader.TimeDateStamp);

    printf("| OPT MAGIC             : 0x%04X\n", pImageNTHeaders->OptionalHeader.Magic);
    printf("| IMAGE BASE            : 0x%p\n",   (void*)pImageNTHeaders->OptionalHeader.ImageBase);
    printf("| ENTRY POINT           : 0x%08X\n", pImageNTHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("| SIZE OF IMAGE         : 0x%08X\n", pImageNTHeaders->OptionalHeader.SizeOfImage);
    
    printf("| EXPORT DIRECTORY SIZE : %d\n", imageExportDataDirectory.Size);
    printf("| EXPORT DIRECTORY RVA  : 0x%08X\n", imageExportDataDirectory.VirtualAddress);
    
    if (imageExportDataDirectory.VirtualAddress == 0 || imageExportDataDirectory.Size == 0){
        printf("| [!] No exports\n");
    
    }else {
        PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(pImageNTHeaders, lpFileBuffer, imageExportDataDirectory.VirtualAddress, NULL);
        if (!pImageExportDir) {
            printf("[!] Failed to map export directory\n");
        } else {
            char *dllName = (char *)ImageRvaToVa(pImageNTHeaders, lpFileBuffer, pImageExportDir->Name, NULL);
            printf("| DLL NAME       : %s\n", dllName);
            printf("| ORDINAL BASE   : %d\n", pImageExportDir->Base);
            printf("| # FUNCTIONS    : %d\n", pImageExportDir->NumberOfFunctions);
            printf("| # NAMES        : %d\n", pImageExportDir->NumberOfNames);

            DWORD* pFunctions = (DWORD*)ImageRvaToVa(pImageNTHeaders, lpFileBuffer, pImageExportDir->AddressOfFunctions, NULL);
            DWORD* pNames     = (DWORD*)ImageRvaToVa(pImageNTHeaders, lpFileBuffer, pImageExportDir->AddressOfNames, NULL);
            WORD*  pOrdinals  = (WORD*) ImageRvaToVa(pImageNTHeaders, lpFileBuffer, pImageExportDir->AddressOfNameOrdinals, NULL);
            
            for (DWORD i = 0; i < pImageExportDir->NumberOfNames; i++) {
                char* funcName = (char*)ImageRvaToVa(pImageNTHeaders, lpFileBuffer, pNames[i], NULL);
                WORD  idx      = pOrdinals[i];
                DWORD funcRva  = pFunctions[idx];
                DWORD ordinal  = pImageExportDir->Base + idx;

                if (funcRva >= imageExportDataDirectory.VirtualAddress &&
                    funcRva <  imageExportDataDirectory.VirtualAddress + imageExportDataDirectory.Size) {
                    char* fwd = (char*)ImageRvaToVa(pImageNTHeaders, lpFileBuffer, funcRva, NULL);
                    printf("| [%4d] %-40s -> FORWARD: %s\n", ordinal, funcName, fwd);
                } else {
                    printf("| [%4d] %-40s @ RVA 0x%08X\n", ordinal, funcName, funcRva);
                }
            }
        }
    
    }   


    VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
    return 0;
    

}