#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "DLL Injection!", "DLL Injection!", 0);
        break;
    }
}