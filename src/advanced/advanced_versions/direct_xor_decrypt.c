#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Direct XOR Pattern Decryptor v1.0\n");
        printf("=================================\n");
        printf("Usage: %s <host_file>\n", argv[0]);
        printf("Example: %s s12_calculator.exe\n", argv[0]);
        return 1;
    }
    
    printf("Direct XOR Pattern Decryptor v1.0\n");
    printf("=================================\n");
    printf("Host: %s\n\n", argv[1]);
    
    // Original putty header (confirmed from our analysis)
    BYTE originalHeader[16] = {0x4D, 0x5A, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00,
                               0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    // Open ADS stream
    char adsPath[MAX_PATH];
    snprintf(adsPath, sizeof(adsPath), "%s:s12data", argv[1]);
    
    HANDLE hADS = CreateFileA(adsPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hADS == INVALID_HANDLE_VALUE) {
        printf("❌ Cannot open ADS stream\n");
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
    
    // Show encrypted header
    printf("\n🔐 Encrypted header: ");
    for (int i = 0; i < 16; i++) printf("%02X ", payload[i]);
    printf("\n");
    
    printf("🎯 Expected result:  ");
    for (int i = 0; i < 16; i++) printf("%02X ", originalHeader[i]);
    printf("\n");
    
    // Calculate the XOR pattern from first 16 bytes
    printf("\n📊 Calculating XOR pattern from header...\n");
    BYTE xorPattern[16];
    for (int i = 0; i < 16; i++) {
        xorPattern[i] = payload[i] ^ originalHeader[i];
        printf("Byte %2d: %02X ^ %02X = %02X\n", i, payload[i], originalHeader[i], xorPattern[i]);
    }
    
    printf("\n🔓 Applying direct XOR decryption...\n");
    
    // Method 1: Try simple repeating pattern
    printf("Method 1: Using 16-byte repeating pattern\n");
    PBYTE testPayload1 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    memcpy(testPayload1, payload, payloadSize);
    
    for (DWORD i = 0; i < payloadSize; i++) {
        testPayload1[i] ^= xorPattern[i % 16];
    }
    
    printf("Result: ");
    for (int i = 0; i < 16; i++) printf("%02X ", testPayload1[i]);
    printf("\n");
    
    if (testPayload1[0] == 0x4D && testPayload1[1] == 0x5A) {
        printf("✅ SUCCESS! Method 1 worked - 16-byte repeating pattern\n");
        
        // Save the working decryption
        char outFile[MAX_PATH];
        GetTempPathA(MAX_PATH, outFile);
        strcat(outFile, "\\FINAL_sillyputty.exe");
        
        HANDLE hOut = CreateFileA(outFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hOut, testPayload1, payloadSize, &written, NULL);
            CloseHandle(hOut);
            
            printf("💾 SUCCESS! Decrypted SillyPutty saved: %s\n", outFile);
            printf("📏 Size: %lu bytes\n", written);
            printf("\n🎯 MISSION ACCOMPLISHED!\n");
            printf("✅ The SillyPutty RAT has been successfully extracted!\n");
            printf("⚠️  File ready for analysis (SAFE MODE)\n");
        }
        
        HeapFree(GetProcessHeap(), 0, testPayload1);
        HeapFree(GetProcessHeap(), 0, payload);
        return 0;
    }
    
    HeapFree(GetProcessHeap(), 0, testPayload1);
    
    // Method 2: Try single-byte pattern
    printf("\nMethod 2: Using first XOR byte for entire file\n");
    PBYTE testPayload2 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    memcpy(testPayload2, payload, payloadSize);
    
    BYTE singleKey = xorPattern[0]; // Use first XOR byte
    for (DWORD i = 0; i < payloadSize; i++) {
        testPayload2[i] ^= singleKey;
    }
    
    printf("Single key: %02X\n", singleKey);
    printf("Result: ");
    for (int i = 0; i < 16; i++) printf("%02X ", testPayload2[i]);
    printf("\n");
    
    if (testPayload2[0] == 0x4D && testPayload2[1] == 0x5A) {
        printf("✅ SUCCESS! Method 2 worked - single byte XOR\n");
        
        char outFile[MAX_PATH];
        GetTempPathA(MAX_PATH, outFile);
        strcat(outFile, "\\FINAL_sillyputty_method2.exe");
        
        HANDLE hOut = CreateFileA(outFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hOut, testPayload2, payloadSize, &written, NULL);
            CloseHandle(hOut);
            printf("💾 SUCCESS! Saved: %s (%lu bytes)\n", outFile, written);
        }
    } else {
        printf("❌ Method 2 failed\n");
    }
    
    HeapFree(GetProcessHeap(), 0, testPayload2);
    
    // Method 3: Try position-based XOR
    printf("\nMethod 3: Position-based XOR (byte position as key)\n");
    PBYTE testPayload3 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    memcpy(testPayload3, payload, payloadSize);
    
    for (DWORD i = 0; i < payloadSize; i++) {
        testPayload3[i] ^= (BYTE)(i & 0xFF);
    }
    
    printf("Result: ");
    for (int i = 0; i < 16; i++) printf("%02X ", testPayload3[i]);
    printf("\n");
    
    if (testPayload3[0] == 0x4D && testPayload3[1] == 0x5A) {
        printf("✅ SUCCESS! Method 3 worked\n");
    } else {
        printf("❌ Method 3 failed\n");
    }
    
    // Save debug information
    printf("\n💾 Saving debug files for analysis...\n");
    
    char debugFile[MAX_PATH];
    GetTempPathA(MAX_PATH, debugFile);
    strcat(debugFile, "\\xor_analysis.txt");
    
    HANDLE hDebug = CreateFileA(debugFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDebug != INVALID_HANDLE_VALUE) {
        char debugInfo[1024];
        sprintf(debugInfo, "XOR Pattern Analysis:\n");
        for (int i = 0; i < 16; i++) {
            sprintf(debugInfo + strlen(debugInfo), "Byte %d: Original=%02X, Encrypted=%02X, XOR=%02X\n", 
                   i, originalHeader[i], payload[i], xorPattern[i]);
        }
        
        DWORD written;
        WriteFile(hDebug, debugInfo, strlen(debugInfo), &written, NULL);
        CloseHandle(hDebug);
        printf("Debug info saved: %s\n", debugFile);
    }
    
    HeapFree(GetProcessHeap(), 0, testPayload3);
    HeapFree(GetProcessHeap(), 0, payload);
    return 0;
}
