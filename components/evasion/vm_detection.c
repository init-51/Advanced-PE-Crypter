#include <windows.h>
#include <stdio.h>
#include "../intrin.h"

BOOL DetectVMRegistry() {
    const char* vm_registry_keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 
        "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        "SYSTEM\\ControlSet001\\Services\\VBoxService",
        "SOFTWARE\\VMware, Inc.\\VMware",
        "SOFTWARE\\Oracle\\VirtualBox",
        NULL
    };
    
    HKEY hKey;
    for (int i = 0; vm_registry_keys[i] != NULL; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vm_registry_keys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return TRUE;
        }
    }
    
    return FALSE;
}

BOOL DetectVMHardware() {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    
    // Check for hypervisor bit
    if (cpuInfo[2] & 0x80000000) {
        return TRUE; // Hypervisor present bit set
    }
    
    // Check CPUID leaf 0x40000000 for hypervisor info
    __cpuid(cpuInfo, 0x40000000);
    if (cpuInfo[0] >= 0x40000000) {
        char hypervisor[13];
        memcpy(hypervisor, &cpuInfo[1], 4);
        memcpy(hypervisor + 4, &cpuInfo[2], 4);
        memcpy(hypervisor + 8, &cpuInfo[3], 4);
        hypervisor[12] = '\0';
        
        if (strstr(hypervisor, "VMware") || strstr(hypervisor, "VBoxVBox") || 
            strstr(hypervisor, "Microsoft Hv") || strstr(hypervisor, "KVMKVMKVM")) {
            return TRUE;
        }
    }
    
    return FALSE;
}

BOOL IsRunningInVM() {
    return DetectVMRegistry() || DetectVMHardware();
}
