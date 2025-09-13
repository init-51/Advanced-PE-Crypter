#include <windows.h>
#include <stdio.h>

#define LZSS_WINDOW_SIZE 4096
#define LZSS_LOOKAHEAD_SIZE 18
#define LZSS_THRESHOLD 2

typedef struct _LZSS_CONTEXT {
    BYTE window[LZSS_WINDOW_SIZE];
    DWORD windowPos;
    DWORD lookaheadPos;
    BYTE lookahead[LZSS_LOOKAHEAD_SIZE];
} LZSS_CONTEXT;

// Initialize LZSS compression context
BOOL InitializeLZSS(LZSS_CONTEXT* ctx) {
    memset(ctx, 0, sizeof(LZSS_CONTEXT));
    memset(ctx->window, ' ', LZSS_WINDOW_SIZE);
    return TRUE;
}

// Find longest match in sliding window
DWORD FindLongestMatch(LZSS_CONTEXT* ctx, DWORD* matchPos) {
    DWORD maxLength = 0;
    DWORD bestPos = 0;
    
    for (DWORD i = 0; i < LZSS_WINDOW_SIZE; i++) {
        DWORD length = 0;
        
        // Compare sequences
        while (length < LZSS_LOOKAHEAD_SIZE &&
               length < ctx->lookaheadPos &&
               ctx->window[(i + length) % LZSS_WINDOW_SIZE] == ctx->lookahead[length]) {
            length++;
        }
        
        if (length > maxLength && length >= LZSS_THRESHOLD) {
            maxLength = length;
            bestPos = i;
        }
    }
    
    *matchPos = bestPos;
    return maxLength;
}

// Advanced LZSS compression with adaptive window
DWORD CompressLZSSAdvanced(PBYTE input, DWORD inputSize, PBYTE output, DWORD maxOutput) {
    LZSS_CONTEXT ctx;
    InitializeLZSS(&ctx);
    
    DWORD inputPos = 0;
    DWORD outputPos = 0;
    BYTE flagByte = 0;
    DWORD flagPos = outputPos++;
    BYTE flagMask = 1;
    
    // Fill initial lookahead buffer
    for (DWORD i = 0; i < LZSS_LOOKAHEAD_SIZE && i < inputSize; i++) {
        ctx.lookahead[i] = input[inputPos + i];
        ctx.lookaheadPos++;
    }
    
    while (ctx.lookaheadPos > 0 && outputPos < maxOutput - 3) {
        DWORD matchPos, matchLength;
        matchLength = FindLongestMatch(&ctx, &matchPos);
        
        if (matchLength >= LZSS_THRESHOLD) {
            // Encode match
            flagByte |= flagMask;
            
            // Encode position and length
            WORD encoded = (WORD)((matchPos << 4) | (matchLength - LZSS_THRESHOLD));
            output[outputPos++] = (BYTE)(encoded >> 8);
            output[outputPos++] = (BYTE)(encoded & 0xFF);
            
            // Advance input
            for (DWORD i = 0; i < matchLength; i++) {
                // Add to window
                ctx.window[ctx.windowPos] = ctx.lookahead[0];
                ctx.windowPos = (ctx.windowPos + 1) % LZSS_WINDOW_SIZE;
                
                // Shift lookahead
                for (DWORD j = 0; j < ctx.lookaheadPos - 1; j++) {
                    ctx.lookahead[j] = ctx.lookahead[j + 1];
                }
                ctx.lookaheadPos--;
                
                // Fill lookahead
                if (inputPos + LZSS_LOOKAHEAD_SIZE < inputSize && ctx.lookaheadPos < LZSS_LOOKAHEAD_SIZE) {
                    ctx.lookahead[ctx.lookaheadPos++] = input[inputPos + LZSS_LOOKAHEAD_SIZE];
                }
                inputPos++;
            }
        } else {
            // Encode literal
            output[outputPos++] = ctx.lookahead[0];
            
            // Add to window
            ctx.window[ctx.windowPos] = ctx.lookahead[0];
            ctx.windowPos = (ctx.windowPos + 1) % LZSS_WINDOW_SIZE;
            
            // Shift lookahead
            for (DWORD j = 0; j < ctx.lookaheadPos - 1; j++) {
                ctx.lookahead[j] = ctx.lookahead[j + 1];
            }
            ctx.lookaheadPos--;
            
            // Fill lookahead
            if (inputPos + LZSS_LOOKAHEAD_SIZE < inputSize && ctx.lookaheadPos < LZSS_LOOKAHEAD_SIZE) {
                ctx.lookahead[ctx.lookaheadPos++] = input[inputPos + LZSS_LOOKAHEAD_SIZE];
            }
            inputPos++;
        }
        
        flagMask <<= 1;
        if (flagMask == 0) {
            output[flagPos] = flagByte;
            flagByte = 0;
            flagPos = outputPos++;
            flagMask = 1;
        }
    }
    
    // Store final flag byte
    output[flagPos] = flagByte;
    
    return outputPos;
}

// Advanced LZSS decompression
DWORD DecompressLZSSAdvanced(PBYTE input, DWORD inputSize, PBYTE output, DWORD maxOutput) {
    BYTE window[LZSS_WINDOW_SIZE];
    memset(window, ' ', LZSS_WINDOW_SIZE);
    
    DWORD inputPos = 0;
    DWORD outputPos = 0;
    DWORD windowPos = 0;
    
    while (inputPos < inputSize && outputPos < maxOutput) {
        BYTE flagByte = input[inputPos++];
        
        for (int i = 0; i < 8 && inputPos < inputSize && outputPos < maxOutput; i++) {
            if (flagByte & (1 << i)) {
                // Decode match
                if (inputPos + 1 >= inputSize) break;
                
                WORD encoded = ((WORD)input[inputPos] << 8) | input[inputPos + 1];
                inputPos += 2;
                
                DWORD matchPos = encoded >> 4;
                DWORD matchLength = (encoded & 0x0F) + LZSS_THRESHOLD;
                
                // Copy from window
                for (DWORD j = 0; j < matchLength && outputPos < maxOutput; j++) {
                    BYTE byte = window[(matchPos + j) % LZSS_WINDOW_SIZE];
                    output[outputPos++] = byte;
                    window[windowPos] = byte;
                    windowPos = (windowPos + 1) % LZSS_WINDOW_SIZE;
                }
            } else {
                // Decode literal
                BYTE byte = input[inputPos++];
                output[outputPos++] = byte;
                window[windowPos] = byte;
                windowPos = (windowPos + 1) % LZSS_WINDOW_SIZE;
            }
        }
    }
    
    return outputPos;
}

// Test function for LZSS compression
int TestLZSSCompression() {
    printf("Testing Advanced LZSS Compression\n");
    printf("=================================\n");
    
    // Test data with repetitive patterns
    BYTE testData[] = "This is a test string with repeated patterns. "
                      "This is a test string with repeated patterns. "
                      "This is a test string with repeated patterns. "
                      "End of test data.";
    DWORD testSize = sizeof(testData) - 1;
    
    printf("Original size: %d bytes\n", testSize);
    printf("Original data: %s\n", testData);
    
    // Compress
    BYTE compressed[1024];
    DWORD compressedSize = CompressLZSSAdvanced(testData, testSize, compressed, sizeof(compressed));
    
    printf("Compressed size: %d bytes\n", compressedSize);
    printf("Compression ratio: %.1f%%\n", (float)compressedSize / testSize * 100.0f);
    
    // Decompress
    BYTE decompressed[1024];
    DWORD decompressedSize = DecompressLZSSAdvanced(compressed, compressedSize, decompressed, sizeof(decompressed));
    decompressed[decompressedSize] = '\0';
    
    printf("Decompressed size: %d bytes\n", decompressedSize);
    printf("Decompressed data: %s\n", decompressed);
    
    // Verify
    BOOL success = (decompressedSize == testSize) && (memcmp(testData, decompressed, testSize) == 0);
    printf("Verification: %s\n", success ? "PASSED" : "FAILED");
    
    return success ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() {
    return TestLZSSCompression();
}
#endif
