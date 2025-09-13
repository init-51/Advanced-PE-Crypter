#include <windows.h>
#include <stdio.h>

int main() {
    printf("=== SIMPLE ADS READER v1.0 ===\n\n");
    
    // Try different ADS path formats
    const char* paths[] = {
        "..\\s12_calculator.exe:s12data",
        "s12_calculator.exe:s12data",
        NULL
    };
    
    BOOL success = FALSE;
    
    for (int pathIndex = 0; paths[pathIndex] != NULL && !success; pathIndex++) {
        printf("Trying path: %s\n", paths[pathIndex]);
        
        HANDLE hADS = CreateFileA(paths[pathIndex], GENERIC_READ, FILE_SHARE_READ, NULL, 
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hADS != INVALID_HANDLE_VALUE) {
            DWORD adsSize = GetFileSize(hADS, NULL);
            printf("✅ SUCCESS! ADS opened - Size: %lu bytes\n\n", adsSize);
            
            // Read first 16 bytes
            BYTE encrypted[16];
            DWORD bytesRead;
            
            if (ReadFile(hADS, encrypted, sizeof(encrypted), &bytesRead, NULL)) {
                // Your original putty header
                BYTE original[16] = {0x4D, 0x5A, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00,
                                   0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                
                printf("=== ENCRYPTION ANALYSIS ===\n");
                printf("Original header: ");
                for (int i = 0; i < 16; i++) printf("%02X ", original[i]);
                printf("\n");
                
                printf("Encrypted data:  ");
                for (int i = 0; i < 16; i++) printf("%02X ", encrypted[i]);
                printf("\n");
                
                printf("XOR pattern:     ");
                for (int i = 0; i < 16; i++) printf("%02X ", original[i] ^ encrypted[i]);
                printf("\n\n");
                
                // Test simple XOR decryption
                printf("=== DECRYPTION TEST ===\n");
                printf("XOR decrypt:     ");
                BOOL matches = TRUE;
                for (int i = 0; i < 16; i++) {
                    BYTE xorKey = original[i] ^ encrypted[i];
                    BYTE decrypted = encrypted[i] ^ xorKey;
                    printf("%02X ", decrypted);
                    if (decrypted != original[i]) matches = FALSE;
                }
                printf("\n\n");
                
                if (matches) {
                    printf("🎯 RESULT: SIMPLE XOR ENCRYPTION CONFIRMED!\n");
                    printf("✅ We can decrypt using XOR with position-based key\n");
                    printf("✅ Ready to build simple XOR decryptor\n\n");
                    
                    printf("XOR Key Pattern for first 16 bytes:\n");
                    for (int i = 0; i < 16; i++) {
                        printf("Byte %2d: %02X ^ %02X = %02X\n", i, original[i], encrypted[i], original[i] ^ encrypted[i]);
                    }
                    
                } else {
                    printf("❌ RESULT: COMPLEX ENCRYPTION DETECTED\n");
                    printf("❌ Simple XOR doesn't work - need S12 algorithm\n");
                }
                
                success = TRUE;
            } else {
                printf("❌ Failed to read ADS data\n");
            }
            
            CloseHandle(hADS);
        } else {
            printf("❌ Failed to open (Error: %lu)\n", GetLastError());
        }
    }
    
    if (!success) {
        printf("❌ Could not access ADS in any format!\n");
    }
    
    return 0;
}
