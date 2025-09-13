#include <windows.h>
#include <stdio.h>

int main() {
    printf("=== CORRECT HEADER ANALYSIS ===\n\n");
    
    // The correct original header from your data
    BYTE originalHeader[16] = {0x4D, 0x5A, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 
                               0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    // Read encrypted ADS data
    HANDLE hADS = CreateFileA("..\\s12_calculator.exe:s12data", GENERIC_READ, 
                             FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hADS != INVALID_HANDLE_VALUE) {
        BYTE encBytes[16];
        DWORD bytesRead;
        ReadFile(hADS, encBytes, sizeof(encBytes), &bytesRead, NULL);
        CloseHandle(hADS);
        
        printf("Original header:  ");
        for (int i = 0; i < 16; i++) printf("%02X ", originalHeader[i]);
        printf("\n");
        
        printf("Encrypted header: ");
        for (int i = 0; i < 16; i++) printf("%02X ", encBytes[i]);
        printf("\n");
        
        printf("XOR pattern:      ");
        for (int i = 0; i < 16; i++) printf("%02X ", originalHeader[i] ^ encBytes[i]);
        printf("\n\n");
        
        // Test simple XOR reversal
        printf("Simple XOR test:  ");
        for (int i = 0; i < 16; i++) {
            BYTE decrypted = encBytes[i] ^ (originalHeader[i] ^ encBytes[i]);
            printf("%02X ", decrypted);
        }
        printf("\n");
        
        printf("\nAnalysis: If simple XOR test matches original, encryption is simple XOR.\n");
        printf("If not, more complex algorithm is used.\n");
    } else {
        printf("Error: Cannot find s12_calculator.exe:s12data\n");
        printf("Make sure you're in the right directory with the encrypted file.\n");
    }
    
    return 0;
}
