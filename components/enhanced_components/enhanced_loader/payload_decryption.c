#include "enhanced_loader.h"

BOOL DecryptPayload(PVOID pEncrypted, DWORD dwSize, LPCSTR lpKey, PVOID* ppDecrypted, PDWORD pdwDecryptedSize) {
    if (!pEncrypted || !dwSize || !lpKey || !ppDecrypted || !pdwDecryptedSize) {
        return FALSE;
    }
    
    // Allocate memory for decrypted payload
    PVOID pDecrypted = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pDecrypted) {
        return FALSE;
    }
    
    // Enhanced XOR decryption with key scheduling
    BYTE keySchedule[256];
    DWORD keyLen = strlen(lpKey);
    
    // Initialize key schedule
    for (int i = 0; i < 256; i++) {
        keySchedule[i] = (BYTE)(lpKey[i % keyLen] ^ (i & 0xFF));
    }
    
    // Additional key mixing
    for (int i = 0; i < 256; i++) {
        int j = (i + keySchedule[i]) % 256;
        BYTE temp = keySchedule[i];
        keySchedule[i] = keySchedule[j];
        keySchedule[j] = temp;
    }
    
    // Decrypt with scheduled key
    PBYTE pSrc = (PBYTE)pEncrypted;
    PBYTE pDst = (PBYTE)pDecrypted;
    
    for (DWORD i = 0; i < dwSize; i++) {
        pDst[i] = pSrc[i] ^ keySchedule[i % 256];
    }
    
    *ppDecrypted = pDecrypted;
    *pdwDecryptedSize = dwSize;
    
    return TRUE;
}
