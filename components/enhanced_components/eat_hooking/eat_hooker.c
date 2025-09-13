#include "eat_hooker.h"
#include <stdio.h>

static EAT_HOOK_CONTEXT g_HookContext = { 0 };

BOOL InitializeEATHooking() {
    if (g_HookContext.bInitialized) return TRUE;
    
    InitializeCriticalSection(&g_HookContext.csHookList);
    g_HookContext.pHookList = NULL;
    g_HookContext.bInitialized = TRUE;
    
    return TRUE;
}

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(HMODULE hModule) {
    if (!hModule) return NULL;
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    
    DWORD exportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRVA) {
        return NULL;
    }
    
    return (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportRVA);
}

DWORD GetExportRVA(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_EXPORT_DIRECTORY pExportDir = GetExportDirectory(hModule);
    if (!pExportDir) return 0;
    
    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR pFunctionName = (LPCSTR)((BYTE*)hModule + pAddressOfNames[i]);
        if (lstrcmpA(pFunctionName, lpProcName) == 0) {
            WORD ordinal = pAddressOfNameOrdinals[i];
            return pAddressOfFunctions[ordinal];
        }
    }
    
    return 0;
}

BOOL ModifyEATEntry(HMODULE hModule, DWORD dwFunctionRVA, PVOID pNewFunction) {
    PIMAGE_EXPORT_DIRECTORY pExportDir = GetExportDirectory(hModule);
    if (!pExportDir) return FALSE;
    
    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);
    
    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
        if (pAddressOfFunctions[i] == dwFunctionRVA) {
            DWORD oldProtect;
            if (!VirtualProtect(&pAddressOfFunctions[i], sizeof(DWORD), PAGE_READWRITE, &oldProtect)) {
                return FALSE;
            }
            
            DWORD newRVA = (DWORD)((BYTE*)pNewFunction - (BYTE*)hModule);
            pAddressOfFunctions[i] = newRVA;
            
            VirtualProtect(&pAddressOfFunctions[i], sizeof(DWORD), oldProtect, &oldProtect);
            return TRUE;
        }
    }
    
    return FALSE;
}

BOOL HookExportFunction(HMODULE hModule, LPCSTR lpProcName, PVOID pHookFunction, PVOID* ppOriginalFunction) {
    if (!g_HookContext.bInitialized && !InitializeEATHooking()) {
        return FALSE;
    }
    
    DWORD originalRVA = GetExportRVA(hModule, lpProcName);
    if (!originalRVA) return FALSE;
    
    PVOID pOriginalFunction = (PVOID)((BYTE*)hModule + originalRVA);
    if (ppOriginalFunction) {
        *ppOriginalFunction = pOriginalFunction;
    }
    
    PHOOK_ENTRY pHookEntry = (PHOOK_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOOK_ENTRY));
    if (!pHookEntry) return FALSE;
    
    pHookEntry->hModule = hModule;
    pHookEntry->lpProcName = lpProcName;
    pHookEntry->pOriginalFunction = pOriginalFunction;
    pHookEntry->pHookFunction = pHookFunction;
    pHookEntry->dwOriginalRVA = originalRVA;
    
    if (!ModifyEATEntry(hModule, originalRVA, pHookFunction)) {
        HeapFree(GetProcessHeap(), 0, pHookEntry);
        return FALSE;
    }
    
    EnterCriticalSection(&g_HookContext.csHookList);
    pHookEntry->pNext = g_HookContext.pHookList;
    g_HookContext.pHookList = pHookEntry;
    LeaveCriticalSection(&g_HookContext.csHookList);
    
    return TRUE;
}

BOOL UnhookExportFunction(HMODULE hModule, LPCSTR lpProcName) {
    if (!g_HookContext.bInitialized) return FALSE;
    
    EnterCriticalSection(&g_HookContext.csHookList);
    PHOOK_ENTRY pCurrent = g_HookContext.pHookList;
    PHOOK_ENTRY pPrevious = NULL;
    
    while (pCurrent) {
        if (pCurrent->hModule == hModule && lstrcmpA(pCurrent->lpProcName, lpProcName) == 0) {
            ModifyEATEntry(hModule, (DWORD)((BYTE*)pCurrent->pHookFunction - (BYTE*)hModule), (PVOID)((BYTE*)hModule + pCurrent->dwOriginalRVA));
            
            if (pPrevious) {
                pPrevious->pNext = pCurrent->pNext;
            } else {
                g_HookContext.pHookList = pCurrent->pNext;
            }
            
            HeapFree(GetProcessHeap(), 0, pCurrent);
            LeaveCriticalSection(&g_HookContext.csHookList);
            return TRUE;
        }
        
        pPrevious = pCurrent;
        pCurrent = pCurrent->pNext;
    }
    
    LeaveCriticalSection(&g_HookContext.csHookList);
    return FALSE;
}

BOOL UnhookAllFunctions() {
    if (!g_HookContext.bInitialized) return TRUE;
    
    EnterCriticalSection(&g_HookContext.csHookList);
    
    PHOOK_ENTRY pCurrent = g_HookContext.pHookList;
    while (pCurrent) {
        PHOOK_ENTRY pNext = pCurrent->pNext;
        ModifyEATEntry(pCurrent->hModule, 
                       (DWORD)((BYTE*)pCurrent->pHookFunction - (BYTE*)pCurrent->hModule), 
                       (PVOID)((BYTE*)pCurrent->hModule + pCurrent->dwOriginalRVA));
        HeapFree(GetProcessHeap(), 0, pCurrent);
        pCurrent = pNext;
    }
    
    g_HookContext.pHookList = NULL;
    LeaveCriticalSection(&g_HookContext.csHookList);
    
    return TRUE;
}

VOID CleanupEATHooking() {
    if (!g_HookContext.bInitialized) return;
    
    UnhookAllFunctions();
    DeleteCriticalSection(&g_HookContext.csHookList);
    g_HookContext.bInitialized = FALSE;
}
