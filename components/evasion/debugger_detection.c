#include <windows.h>
#include <tlhelp32.h>
#include "../winternl.h"
#include "../intrin.h"

BOOL DetectDebuggerStandard() {
    return IsDebuggerPresent();
}

BOOL DetectRemoteDebugger() {
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    return isDebugged;
}

BOOL DetectDebuggerPEB() {
    DWORD_PTR peb = __readfsdword(0x30);
    if (peb) {
        BOOL beingDebugged = *(BYTE*)(peb + 0x02);
        return beingDebugged;
    }
    return FALSE;
}

BOOL DetectDebuggerNtGlobalFlag() {
    DWORD_PTR peb = __readfsdword(0x30);
    if (peb) {
        DWORD ntGlobalFlag = *(DWORD*)(peb + 0x68);  // NtGlobalFlag offset for x86
        return (ntGlobalFlag & 0x70) != 0;
    }
    return FALSE;
}

BOOL DetectHardwareBreakpoints() {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
    }
    
    return FALSE;
}

BOOL DetectDebuggerTiming() {
    LARGE_INTEGER start, end, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    
    // Simple operation
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }
    
    QueryPerformanceCounter(&end);
    
    // Calculate time in microseconds
    double timeElapsed = (double)(end.QuadPart - start.QuadPart) * 1000000.0 / frequency.QuadPart;
    
    // If operation took unusually long, likely being debugged
    return timeElapsed > 1000.0; // 1ms threshold
}

BOOL IsBeingDebugged() {
    if (DetectDebuggerStandard()) return TRUE;
    if (DetectRemoteDebugger()) return TRUE;
    if (DetectDebuggerPEB()) return TRUE;
    if (DetectDebuggerNtGlobalFlag()) return TRUE;
    if (DetectHardwareBreakpoints()) return TRUE;
    if (DetectDebuggerTiming()) return TRUE;
    
    return FALSE;
}
