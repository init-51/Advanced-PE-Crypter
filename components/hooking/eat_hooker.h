#ifndef EAT_HOOKER_H
#define EAT_HOOKER_H

#include <windows.h>
#include "../winternl.h"  // ← Change this line (was missing ../)

typedef struct _HOOK_ENTRY {
    HMODULE hModule;
    LPCSTR lpProcName;
    PVOID pOriginalFunction;
    PVOID pHookFunction;
    DWORD dwOriginalRVA;
    struct _HOOK_ENTRY* pNext;
} HOOK_ENTRY, *PHOOK_ENTRY;

typedef struct _EAT_HOOK_CONTEXT {
    PHOOK_ENTRY pHookList;
    CRITICAL_SECTION csHookList;
    BOOL bInitialized;
} EAT_HOOK_CONTEXT, *PEAT_HOOK_CONTEXT;

// Core functions
BOOL InitializeEATHooking();
BOOL HookExportFunction(HMODULE hModule, LPCSTR lpProcName, PVOID pHookFunction, PVOID* ppOriginalFunction);
BOOL UnhookExportFunction(HMODULE hModule, LPCSTR lpProcName);
BOOL UnhookAllFunctions();
VOID CleanupEATHooking();

// Utilities
PIMAGE_EXPORT_DIRECTORY GetExportDirectory(HMODULE hModule);
DWORD GetExportRVA(HMODULE hModule, LPCSTR lpProcName);
BOOL ModifyEATEntry(HMODULE hModule, DWORD dwFunctionRVA, PVOID pNewFunction);

// Hook handlers
LPVOID WINAPI HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL WINAPI HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL InitializeAPIHooks();

#endif
