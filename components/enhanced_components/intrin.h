#ifndef INTRIN_H_CUSTOM
#define INTRIN_H_CUSTOM

#include <windows.h>

// Custom CPUID implementation for GCC
static inline void __cpuid(int cpuInfo[4], int function_id) {
    #ifdef __GNUC__
        #ifdef _WIN64
            __asm__ volatile (
                "cpuid"
                : "=a" (cpuInfo[0]), "=b" (cpuInfo[1]), "=c" (cpuInfo[2]), "=d" (cpuInfo[3])
                : "a" (function_id)
                : "rbx", "rcx", "rdx"
            );
        #else
            __asm__ volatile (
                "pushl %%ebx       \n\t"
                "cpuid             \n\t"
                "movl %%ebx, %1    \n\t"
                "popl %%ebx        \n\t"
                : "=a" (cpuInfo[0]), "=r" (cpuInfo[1]), "=c" (cpuInfo[2]), "=d" (cpuInfo[3])
                : "a" (function_id)
                : "cc"
            );
        #endif
    #else
        cpuInfo[0] = cpuInfo[1] = cpuInfo[2] = cpuInfo[3] = 0;
    #endif
}

// Custom read FS/GS for GCC
static inline DWORD_PTR __readfsdword(DWORD offset) {
    DWORD_PTR result;
    #ifdef __GNUC__
        #ifdef _WIN64
            __asm__ volatile ("movq %%gs:%1, %0" : "=r" (result) : "m" (*(DWORD_PTR*)offset));
        #else
            __asm__ volatile ("movl %%fs:%1, %0" : "=r" (result) : "m" (*(DWORD_PTR*)offset));
        #endif
    #else
        result = 0;
    #endif
    return result;
}

static inline DWORD_PTR __readgsqword(DWORD offset) {
    DWORD_PTR result;
    #ifdef __GNUC__
        #ifdef _WIN64
            __asm__ volatile ("movq %%gs:%1, %0" : "=r" (result) : "m" (*(DWORD_PTR*)offset));
        #else
            result = __readfsdword(offset);
        #endif
    #else
        result = 0;
    #endif
    return result;
}

#endif
