/*
 *  Copyright (C) 1999,2003,2007,2008,2009,2010  Free Software Foundation, Inc.
 *
 *  multiboot2.h - Multiboot 2 header file.
 *
 *  Based on grub-2.00/include/multiboot2.h file.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL ANY
 *  DEVELOPER OR DISTRIBUTOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 *  IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __MULTIBOOT2_H__
#define __MULTIBOOT2_H__

/* The magic field should contain this.  */
#define MULTIBOOT2_HEADER_MAGIC                         0xe85250d6

/* This should be in %eax on x86 architecture.  */
#define MULTIBOOT2_BOOTLOADER_MAGIC                     0x36d76289

/* How many bytes from the start of the file we search for the header.  */
#define MULTIBOOT2_SEARCH                               32768

/* Multiboot 2 header alignment. */
#define MULTIBOOT2_HEADER_ALIGN                         8

/* Alignment of multiboot 2 modules.  */
#define MULTIBOOT2_MOD_ALIGN                            0x00001000

/* Alignment of the multiboot 2 info structure.  */
#define MULTIBOOT2_INFO_ALIGN                           0x00000008

/* Multiboot 2 architectures. */
#define MULTIBOOT2_ARCHITECTURE_I386                    0
#define MULTIBOOT2_ARCHITECTURE_MIPS32                  4

/* Header tag types. */
#define MULTIBOOT2_HEADER_TAG_END                       0
#define MULTIBOOT2_HEADER_TAG_INFORMATION_REQUEST       1
#define MULTIBOOT2_HEADER_TAG_ADDRESS                   2
#define MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS             3
#define MULTIBOOT2_HEADER_TAG_CONSOLE_FLAGS             4
#define MULTIBOOT2_HEADER_TAG_FRAMEBUFFER               5
#define MULTIBOOT2_HEADER_TAG_MODULE_ALIGN              6
#define MULTIBOOT2_HEADER_TAG_EFI_BS                    7
#define MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS_EFI32       8
#define MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS_EFI64       9
#define MULTIBOOT2_HEADER_TAG_RELOCATABLE               10

/* Header tag flags. */
#define MULTIBOOT2_HEADER_TAG_REQUIRED                  0
#define MULTIBOOT2_HEADER_TAG_OPTIONAL                  1

/* Where image should be loaded (suggestion not requirement). */
#define MULTIBOOT2_LOAD_PREFERENCE_NONE                 0
#define MULTIBOOT2_LOAD_PREFERENCE_LOW                  1
#define MULTIBOOT2_LOAD_PREFERENCE_HIGH                 2

/* Header console tag console_flags. */
#define MULTIBOOT2_CONSOLE_FLAGS_CONSOLE_REQUIRED       1
#define MULTIBOOT2_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED     2

/* Flags set in the 'flags' member of the multiboot header.  */
#define MULTIBOOT2_TAG_TYPE_END                         0
#define MULTIBOOT2_TAG_TYPE_CMDLINE                     1
#define MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME            2
#define MULTIBOOT2_TAG_TYPE_MODULE                      3
#define MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO               4
#define MULTIBOOT2_TAG_TYPE_BOOTDEV                     5
#define MULTIBOOT2_TAG_TYPE_MMAP                        6
#define MULTIBOOT2_TAG_TYPE_VBE                         7
#define MULTIBOOT2_TAG_TYPE_FRAMEBUFFER                 8
#define MULTIBOOT2_TAG_TYPE_ELF_SECTIONS                9
#define MULTIBOOT2_TAG_TYPE_APM                         10
#define MULTIBOOT2_TAG_TYPE_EFI32                       11
#define MULTIBOOT2_TAG_TYPE_EFI64                       12
#define MULTIBOOT2_TAG_TYPE_SMBIOS                      13
#define MULTIBOOT2_TAG_TYPE_ACPI_OLD                    14
#define MULTIBOOT2_TAG_TYPE_ACPI_NEW                    15
#define MULTIBOOT2_TAG_TYPE_NETWORK                     16
#define MULTIBOOT2_TAG_TYPE_EFI_MMAP                    17
#define MULTIBOOT2_TAG_TYPE_EFI_BS                      18
#define MULTIBOOT2_TAG_TYPE_EFI32_IH                    19
#define MULTIBOOT2_TAG_TYPE_EFI64_IH                    20
#define MULTIBOOT2_TAG_TYPE_LOAD_BASE_ADDR              21

/* Multiboot 2 tag alignment. */
#define MULTIBOOT2_TAG_ALIGN                            8

/* Memory types. */
#define MULTIBOOT2_MEMORY_AVAILABLE                     1
#define MULTIBOOT2_MEMORY_RESERVED                      2
#define MULTIBOOT2_MEMORY_ACPI_RECLAIMABLE              3
#define MULTIBOOT2_MEMORY_NVS                           4
#define MULTIBOOT2_MEMORY_BADRAM                        5

/* Framebuffer types. */
#define MULTIBOOT2_FRAMEBUFFER_TYPE_INDEXED             0
#define MULTIBOOT2_FRAMEBUFFER_TYPE_RGB                 1
#define MULTIBOOT2_FRAMEBUFFER_TYPE_EGA_TEXT            2

#ifndef __ASSEMBLY__
typedef struct {
    u32 total_size;
    u32 reserved;
} multiboot2_fixed_t;

typedef struct {
    u32 type;
    u32 size;
} multiboot2_tag_t;

typedef struct {
    u32 type;
    u32 size;
    u32 load_base_addr;
} multiboot2_tag_load_base_addr_t;

typedef struct {
    u32 type;
    u32 size;
    char string[];
} multiboot2_tag_string_t;

typedef struct {
    u32 type;
    u32 size;
    u32 mem_lower;
    u32 mem_upper;
} multiboot2_tag_basic_meminfo_t;

typedef struct {
    u64 addr;
    u64 len;
    u32 type;
    u32 zero;
} multiboot2_memory_map_t;

typedef struct {
    u32 type;
    u32 size;
    u32 entry_size;
    u32 entry_version;
    multiboot2_memory_map_t entries[];
} multiboot2_tag_mmap_t;

typedef struct {
    u32 type;
    u32 size;
    u64 pointer;
} multiboot2_tag_efi64_t;

typedef struct {
    u32 type;
    u32 size;
    u64 pointer;
} multiboot2_tag_efi64_ih_t;

typedef struct {
    u32 type;
    u32 size;
    u32 mod_start;
    u32 mod_end;
    char cmdline[];
} multiboot2_tag_module_t;
#endif /* __ASSEMBLY__ */

#endif /* __MULTIBOOT2_H__ */
