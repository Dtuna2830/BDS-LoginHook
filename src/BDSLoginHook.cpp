#include <Windows.h>
#include <iostream>
#include <MinHook.h>

struct ServerNetworkHandler;
struct NetworkIdentifier;
struct LoginPacket;

typedef VOID(__fastcall *originLoginPacketHandler)(ServerNetworkHandler *thisptr, const NetworkIdentifier *a2, const LoginPacket *a3);

static originLoginPacketHandler oLoginPacketHandler = nullptr;
static LPVOID targetAddress = nullptr;

VOID __fastcall hookedLoginPacketHandler(ServerNetworkHandler *thisptr, const NetworkIdentifier *a2, const LoginPacket *a3)
{
    std::cout << "Login hook ran!" << std::endl;
    oLoginPacketHandler(thisptr, a2, a3);
}

DWORD WINAPI mainThread(LPVOID lpParam)
{
    HMODULE baseModule = GetModuleHandleA(NULL);
    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(baseModule);
    uintptr_t targetAddr = baseAddress + 0x894160; // 1.20.81.01

    if (MH_Initialize() != MH_OK)
    {
        std::cout << "Failed to initialize MinHook" << std::endl;
        return 0;
    }

    targetAddress = reinterpret_cast<LPVOID>(targetAddr);

    if (MH_CreateHook(targetAddress, &hookedLoginPacketHandler, reinterpret_cast<LPVOID *>(&oLoginPacketHandler)) != MH_OK)
    {
        std::cout << "Failed to create hook" << std::endl;
        return 0;
    }

    if (MH_EnableHook(targetAddress) != MH_OK)
    {
        std::cout << "Failed to enable hook" << std::endl;
    }

    return 0;
}

void clean()
{
    if (targetAddress != nullptr)
    {
        if (MH_DisableHook(targetAddress) != MH_OK)
        {
            std::cout << "Failed to disable hook" << std::endl;
        }

        if (MH_RemoveHook(targetAddress) != MH_OK)
        {
            std::cout << "Failed to remove hook" << std::endl;
        }
    }

    if (MH_Uninitialize() != MH_OK)
    {
        std::cout << "Failed to uninitialize MinHook." << std::endl;
    }

    std::cout << "Cleanup completed" << std::endl;
}

// https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, // handle to DLL module
    DWORD fdwReason,    // reason for calling function
    LPVOID lpvReserved) // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(nullptr, 0, mainThread, hinstDLL, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:

        if (lpvReserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }
        clean();
        break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}