#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* maximum reloc.bin file size allowed is 64kb 
 * might give error result if reloc is > 64kb
 */

int main(int argc, char const *argv[])
{
  char *input_stub_file = argv[1];

  void *input = CreateFileA(input_stub_file, GENERIC_READ, 0, NULL,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  LARGE_INTEGER input_file_size;

  GetFileSizeEx(input, &input_file_size);

  unsigned char *input_base = HeapAlloc(GetProcessHeap(), 0x08, 
      (unsigned int)input_file_size.QuadPart);

  unsigned int read_bytes = 0;

  ReadFile(input, input_base, (unsigned int)input_file_size.QuadPart,
      &read_bytes, NULL);

  CloseHandle(input);

  void *reloc = malloc(64 * 1000);
  unsigned char *p = reloc;

  p += 0x02;

  for (unsigned int i = 0; i < (unsigned int)input_file_size.QuadPart; i++)
  {
      if (*(unsigned int*)(input_base + i) == 0xED0000ED)
      {
          *(unsigned short*)p = i;
          p += 0x02;
          memcpy(p, "$GetModuleHandleA", strlen("$GetModuleHandleA") + 1);
          p += strlen("$GetModuleHandleA") + 1;

      } else if (*(unsigned int*)(input_base + i) == 0xEE0000EE) {
          *(unsigned short*)p = i;
          p += 0x02;
          memcpy(p, "$GetProcAddress", strlen("$GetProcAddress") + 1);
          p += strlen("$GetProcAddress") + 1;

      } else if (*(unsigned int*)(input_base + i) == 0xAD0000AD) {
          *(unsigned short*)p = i;
          p += 0x02;
          memcpy(p, "$LoadLibraryA", strlen("$LoadLibraryA") + 1);
          p += strlen("$LoadLibraryA") + 1;

      } else if (*(unsigned int*)(input_base + i) == 0xAF0000AF) {
          *(unsigned short*)p = i;
          p += 0x02;
          memcpy(p, "$VirtualProtect", strlen("$VirtualProtect") + 1);
          p += strlen("$VirtualProtect") + 1;

      } else if (*(unsigned int*)(input_base + i) == 0XAC0000AC) {
          *(unsigned short*)p = i;
          p += 0x02;
          memcpy(p, "$dest", strlen("$dest") + 1);
          p += strlen("$dest") + 1;

      } else if (*(unsigned int*)(input_base + i) == 0XFEE0000) {
          *(unsigned short*)p = i;
          p += 0x02;
          memcpy(p, "$VirtualFree", strlen("$VirtualFree") + 1);
          p += strlen("$VirtualFree") + 1;

      } else if (*(unsigned int*)(input_base + i) == 0XBA0000EE) {
          *(unsigned short*)p = i;
          p += 0x02;
          memcpy(p, "$base", strlen("$base") + 1);
          p += strlen("$base") + 1;

      }
  }

  *(unsigned int*)p = 0;
  p += sizeof(unsigned int);

  unsigned short index = (unsigned short)(p - (unsigned char*)reloc - 0x02);
  *(unsigned short*)reloc = index;

  void *output = CreateFileA("reloc.bin", GENERIC_ALL, FILE_SHARE_READ
      | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

  unsigned int bytes_written = 0;
  WriteFile(output, reloc, (unsigned int)(index + 0x02), &bytes_written, 0);

  CloseHandle(output);
  free(reloc);

  return 0;
}