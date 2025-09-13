#include <stdio.h>
#include <windows.h>
#include <winnt.h>

int main(int argc, char const *argv[])
{
    if (argc > 4)
    {
        char *pefile = argv[1];
        char *stubfile = argv[2];
        char *relocfile = argv[3];
        char *shellcode_arg = argv[4];

        void *stub = NULL, *pe = NULL, *reloc = NULL, *out_file = NULL;
        LARGE_INTEGER stubsize, pesize, relocsize, dist_to_move;
        void *out_base = NULL, *p = NULL;
        unsigned int read_bytes = 0, bytes_written = 0;

        stub = CreateFileA(stubfile, GENERIC_READ, 0, NULL, 
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (stub == 0 || INVALID_HANDLE_VALUE == stub)
        {
            printf("%s %d\n", "Cannot open the stub file", GetLastError());
            return -1;
        }

        pe = CreateFileA(pefile, GENERIC_READ, 0, NULL, 
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (pe == 0 || INVALID_HANDLE_VALUE == pe)
        {
            printf("%s %d\n", "Cannot open the pe file", GetLastError());
            return -1;
        }

        reloc = CreateFileA(relocfile, GENERIC_READ, 0, NULL, 
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (reloc == 0 || INVALID_HANDLE_VALUE == reloc)
        {
            printf("%s %d\n", "Cannot open the reloc file", GetLastError());
            return -1;
        }

        if (!GetFileSizeEx(stub, &stubsize))
        {
            printf("%s %d\n", "Cannot get the size of"
                "supplied stub file", GetLastError());
            return -1;
        }

        if (!GetFileSizeEx(pe, &pesize))
        {
            printf("%s %d\n", "Cannot get the size of"
                "supplied pe file", GetLastError());
            return -1;
        }

        if (!GetFileSizeEx(reloc, &relocsize))
        {
            printf("%s %d\n", "Cannot get the size of"
                "supplied reloc file", GetLastError());
            return -1;
        }

        int size_shellcode = 0;

        if (*shellcode_arg == '1')
           size_shellcode = 4;
        else
           printf("%c :shellcode arg", shellcode_arg);

        out_base = HeapAlloc(GetProcessHeap(), 0x08, (size_t)(relocsize.QuadPart + 
            stubsize.QuadPart + pesize.QuadPart + size_shellcode));

        p = out_base;

        if (!ReadFile(reloc, p, (unsigned int)relocsize.QuadPart, &read_bytes
            , NULL))
        {
            printf("%s %d\n", "Cannot read the reloc file", GetLastError());
            return -1;
        }

        (unsigned char*)p += read_bytes;

        if (!ReadFile(stub, p, 
            (unsigned int)stubsize.QuadPart, &read_bytes, NULL))
        {
            printf("%s %d\n", "Cannot read the stub file", GetLastError());
            return -1;
        }

        (unsigned char*)p += read_bytes;

        if (*shellcode_arg == '1')
        {
            *(unsigned int*)p = (unsigned int)pesize.QuadPart;
            (unsigned char*)p += 4;
        }

        if (!ReadFile(pe, p, 
            (unsigned int)pesize.QuadPart, &read_bytes, NULL))
        {
            printf("%s %d\n", "Cannot read the pe file", GetLastError());
            return -1;
        }

        CloseHandle(reloc);
        CloseHandle(pe);
        CloseHandle(stub);

        out_file = CreateFileA("shellcode.bin", GENERIC_ALL, FILE_SHARE_READ
            | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

        if (!WriteFile(out_file, out_base, (size_t)(relocsize.QuadPart + 
            stubsize.QuadPart + pesize.QuadPart + size_shellcode), &bytes_written, 0))
        {
            printf("%s %d\n", "Cannot write to file", GetLastError());
            return -1;
        }

        CloseHandle(out_file);
        free(out_base);
    }

    return 0;
}