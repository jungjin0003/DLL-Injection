#include <stdio.h>
#include <windows.h>

#define DesiredAccess (PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD)

LPCSTR GetBaseName(LPCSTR path)
{
    ssize_t length = strlen(path);

    for (; length > -1; length--)
    {
        if (path[length] == '\\')
            return path + length + 1;
    }

    return path;
}

void error(LPCSTR FunctionName)
{
    printf("[-] %s Failed\n", FunctionName);
    printf("[*] GetLastError : %d\n", GetLastError());
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("Usage : %s [PID] [DLL Path]\n", GetBaseName(argv[0]));
        printf("ex : %s 1234 C:\\Hack.dll", GetBaseName(argv[0]));
        return -1;
    }

    DWORD PID = atoi(argv[1]);
    LPCSTR Path = argv[2];
    size_t length = strlen(Path);

    printf("[*] Attempting get target process permissions...\n");

    HANDLE hProcess = OpenProcess(DesiredAccess, FALSE, PID);

    if (hProcess == NULL)
    {
        error("OpenProcess");
        return -1;
    }

    printf("[*] OpenProcess success!\n");
    printf("[+] Get process handle : 0x%X\n", hProcess);

    PVOID PathAddress = VirtualAllocEx(hProcess, NULL, length, MEM_COMMIT, PAGE_READWRITE);

    if (PathAddress == NULL)
    {
        error("VirtualAllocEx");
        return -1;
    }

    printf("[*] Allocate buffer to target process success!\n");
    printf("[+] Buffer address is 0x%p\n", PathAddress);

    printf("[*] DLL path writing...\n");

    SIZE_T NumberOfBytesWritten;

    if (WriteProcessMemory(hProcess, PathAddress, Path, length, NULL) == FALSE)
    {
        error("WriteProcessMemory");
        return -1;
    }

    printf("[*] Written DLL Path\n");

    printf("[*] HMODULE of kernel32.dll finding...\n");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    
    if (hKernel32 == NULL)
    {
        error("GetModuleHandleA");
        return -1;
    }

    printf("[*] HMODULE of kernel32.dll found!\n");
    printf("[+] HMODULE of kernel32.dll is 0x%p\n", hKernel32);

    printf("[*] LoadLibraryA address of kernel32.dll finding...\n");

    FARPROC lpLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

    if (lpLoadLibraryA == NULL)
    {
        error("GetProcAddress");
        return -1;
    }

    printf("[*] LoadLibraryA address of kernel32.dll found!\n");
    printf("[+] LoadLibraryA address is 0x%p\n", lpLoadLibraryA);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, lpLoadLibraryA, PathAddress, 0, NULL);

    if (hThread == NULL)
    {
        error("CreateRemoteThread");
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD ExitCode;
    GetExitCodeThread(hThread, &ExitCode);

    if (ExitCode == NULL)
    {
        printf("DLL Injection Failed\n");
        return -1;
    }

    printf("[+] DLL Injection Success!\n");

    return 0;
}