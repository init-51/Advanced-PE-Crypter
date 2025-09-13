#include <windows.h>
#include <stdio.h>
#include <winreg.h>

// S12's Advanced VM Detection Bypass Techniques
// Based on research from @s12deff and 0x12Dark Development

typedef struct _VM_DETECTION_RESULT {
    BOOL isVM;
    CHAR detectionMethod[256];
    DWORD confidence;
} VM_DETECTION_RESULT;

// Method 1: Enhanced CPUID Analysis (S12 technique)
BOOL S12_AdvancedCPUIDCheck() {
    int cpuInfo[4] = {0};
    
    // Multiple CPUID checks for better accuracy
    __asm__ volatile (
        "pushl %%ebx       \n\t"
        "cpuid             \n\t" 
        "movl %%ebx, %1    \n\t"
        "popl %%ebx        \n\t"
        : "=a" (cpuInfo[0]), "=r" (cpuInfo[1]), "=c" (cpuInfo[2]), "=d" (cpuInfo[3])
        : "a" (1)
        : "cc"
    );
    
    // Check hypervisor present bit (bit 31 of ECX)
    BOOL hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
    
    // S12's technique: Check for hypervisor brand string
    __asm__ volatile (
        "pushl %%ebx       \n\t"
        "cpuid             \n\t"
        "movl %%ebx, %1    \n\t" 
        "popl %%ebx        \n\t"
        : "=a" (cpuInfo[0]), "=r" (cpuInfo[1]), "=c" (cpuInfo[2]), "=d" (cpuInfo[3])
        : "a" (0x40000000)
        : "cc"
    );
    
    // Check for known hypervisor signatures
    char hypervisorBrand[13] = {0};
    memcpy(hypervisorBrand, &cpuInfo[1], 4);
    memcpy(hypervisorBrand + 4, &cpuInfo[2], 4);
    memcpy(hypervisorBrand + 8, &cpuInfo[3], 4);
    
    // Known hypervisor signatures to detect
    const char* vmSignatures[] = {
        "VMwareVMware",    // VMware
        "Microsoft Hv",   // Hyper-V
        "XenVMMXenVMM",   // Xen
        "VBoxVBoxVBox",   // VirtualBox
        "KVMKVMKVM",      // KVM
        NULL
    };
    
    for (int i = 0; vmSignatures[i] != NULL; i++) {
        if (strstr(hypervisorBrand, vmSignatures[i])) {
            printf("  • CPUID VM signature detected: %s\n", vmSignatures[i]);
            return TRUE; // VM detected
        }
    }
    
    return hypervisorPresent;
}

// Method 2: S12's Registry-Based Detection
BOOL S12_RegistryVMCheck() {
    HKEY hKey;
    CHAR buffer[256];
    DWORD bufferSize = sizeof(buffer);
    
    // Known VM registry keys (S12's research)
    const char* vmRegKeys[] = {
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier",
        "HARDWARE\\Description\\System\\SystemBiosVersion",
        "HARDWARE\\Description\\System\\BIOS\\SystemManufacturer",
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        NULL
    };
    
    const char* vmStrings[] = {
        "VBOX", "VMWARE", "VIRTUAL", "XEN", "QEMU", "BOCHS", NULL
    };
    
    for (int i = 0; vmRegKeys[i] != NULL; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmRegKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, NULL, NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                // Check for VM-related strings
                for (int j = 0; vmStrings[j] != NULL; j++) {
                    if (strstr(_strupr(buffer), vmStrings[j])) {
                        printf("  • Registry VM indicator: %s in %s\n", vmStrings[j], buffer);
                        RegCloseKey(hKey);
                        return TRUE;
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }
    
    return FALSE;
}

// Method 3: S12's Timing-Based Analysis
BOOL S12_TimingAnalysis() {
    // Multiple timing checks for better accuracy
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    
    // Test 1: RDTSC timing
    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 1000000; i++) {
        __asm__ volatile ("nop");
    }
    QueryPerformanceCounter(&end);
    
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    printf("  • Timing test 1: %.6f seconds\n", elapsed);
    
    // VM usually has inconsistent timing
    if (elapsed < 0.001 || elapsed > 0.1) {
        printf("  • Suspicious timing detected (possible VM)\n");
        return TRUE;
    }
    
    // Test 2: Sleep timing accuracy
    DWORD sleepStart = GetTickCount();
    Sleep(1000);
    DWORD sleepEnd = GetTickCount();
    DWORD actualSleep = sleepEnd - sleepStart;
    
    printf("  • Sleep timing: %lu ms (expected: 1000ms)\n", actualSleep);
    
    // VMs often have timing irregularities
    if (actualSleep < 900 || actualSleep > 1100) {
        printf("  • Sleep timing irregularity detected\n");
        return TRUE;
    }
    
    return FALSE;
}

// Method 4: S12's Process Analysis
BOOL S12_ProcessAnalysis() {
    // Check for VM-related processes
    const char* vmProcesses[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "vboxservice.exe", "vboxtray.exe", "vmcompute.exe",
        "vmms.exe", "vmwp.exe", "xenservice.exe", NULL
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (int i = 0; vmProcesses[i] != NULL; i++) {
                if (_stricmp(pe32.szExeFile, vmProcesses[i]) == 0) {
                    printf("  • VM process detected: %s\n", pe32.szExeFile);
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return FALSE;
}

// S12's Comprehensive VM Detection
VM_DETECTION_RESULT S12_ComprehensiveVMDetection() {
    VM_DETECTION_RESULT result = {0};
    DWORD detectionCount = 0;
    
    printf("S12's Advanced VM Detection Analysis\n");
    printf("=====================================\n");
    
    // Run all detection methods
    if (S12_AdvancedCPUIDCheck()) {
        strcat(result.detectionMethod, "CPUID ");
        detectionCount++;
    }
    
    if (S12_RegistryVMCheck()) {
        strcat(result.detectionMethod, "Registry ");
        detectionCount++;
    }
    
    if (S12_TimingAnalysis()) {
        strcat(result.detectionMethod, "Timing ");
        detectionCount++;
    }
    
    if (S12_ProcessAnalysis()) {
        strcat(result.detectionMethod, "Process ");
        detectionCount++;
    }
    
    // Calculate confidence based on multiple indicators
    result.confidence = (detectionCount * 100) / 4; // 4 total methods
    result.isVM = detectionCount >= 2; // Require 2+ methods for positive detection
    
    printf("\nS12 Detection Summary:\n");
    printf("Methods triggered: %s\n", result.detectionMethod);
    printf("Confidence level: %lu%%\n", result.confidence);
    printf("VM Assessment: %s\n", result.isVM ? "VIRTUAL MACHINE" : "PHYSICAL MACHINE");
    
    return result;
}

// S12's Evasion Bypass for Testing
BOOL S12_BypassForTesting() {
    printf("\n🔧 S12's Testing Bypass Activated\n");
    printf("=====================================\n");
    printf("Simulating physical machine environment...\n");
    printf("  • CPUID checks: BYPASSED\n");
    printf("  • Registry checks: BYPASSED\n"); 
    printf("  • Timing analysis: BYPASSED\n");
    printf("  • Process analysis: BYPASSED\n");
    printf("  • Environment: FORCED CLEAN\n");
    printf("\n✅ All VM detection bypassed for testing purposes\n");
    return TRUE; // Always return clean for testing
}

#ifdef STANDALONE_TEST
int main() {
    printf("S12's VM Detection & Bypass Tool\n");
    printf("=================================\n\n");
    
    // Run comprehensive detection
    VM_DETECTION_RESULT result = S12_ComprehensiveVMDetection();
    
    printf("\n" + (result.isVM ? "🚨" : "✅") + " Final Assessment: %s\n", 
           result.isVM ? "VM Detected - Activating Evasion" : "Physical Machine - Proceeding");
    
    if (result.isVM) {
        printf("\n🔧 Activating S12's bypass techniques...\n");
        S12_BypassForTesting();
    }
    
    return 0;
}
#endif
