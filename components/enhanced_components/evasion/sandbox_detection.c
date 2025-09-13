#include <windows.h>
#include <stdio.h>

BOOL DetectSandboxTiming() {
    DWORD startTime = GetTickCount();
    Sleep(1000);
    DWORD endTime = GetTickCount();
    
    // If sleep was accelerated significantly, likely in sandbox
    if (endTime - startTime < 900) {
        return TRUE;
    }
    
    return FALSE;
}

BOOL DetectSandboxFiles() {
    const char* sandbox_files[] = {
        "C:\\analysis\\malware.exe",
        "C:\\sandbox\\sample.exe", 
        "C:\\sample\\test.exe",
        "C:\\analysis\\sample.exe",
        "C:\\malware.exe",
        "C:\\sample.exe",
        NULL
    };
    
    for (int i = 0; sandbox_files[i] != NULL; i++) {
        if (GetFileAttributesA(sandbox_files[i]) != INVALID_FILE_ATTRIBUTES) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL DetectSandboxUserActivity() {
    POINT cursor1, cursor2;
    GetCursorPos(&cursor1);
    Sleep(2000);
    GetCursorPos(&cursor2);
    
    // Check if mouse moved
    if (cursor1.x == cursor2.x && cursor1.y == cursor2.y) {
        // Check for recent user input
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(LASTINPUTINFO);
        GetLastInputInfo(&lii);
        
        DWORD currentTime = GetTickCount();
        DWORD idleTime = currentTime - lii.dwTime;
        
        // If idle for too long, likely automated environment
        if (idleTime > 30000) { // 30 seconds
            return TRUE;
        }
    }
    
    return FALSE;
}

BOOL IsRunningInSandbox() {
    return DetectSandboxTiming() || DetectSandboxFiles() || DetectSandboxUserActivity();
}
