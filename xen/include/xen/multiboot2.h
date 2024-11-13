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

#include <xen/stdint.h>

typedef struct {
    uint32_t total_size;
    uint32_t reserved;
} multiboot2_fixed_t;

typedef struct {
    uint32_t type;
    uint32_t size;
} multiboot2_tag_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t load_base_addr;
} multiboot2_tag_load_base_addr_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    char string[];
} multiboot2_tag_string_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t mem_lower;
    uint32_t mem_upper;
} multiboot2_tag_basic_meminfo_t;

typedef struct {
    uint64_t addr;
    uint64_t len;
    uint32_t type;
    uint32_t zero;
} multiboot2_memory_map_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t entry_size;
    uint32_t entry_version;
    multiboot2_memory_map_t entries[];
} multiboot2_tag_mmap_t;

typedef struct
{
    uint32_t type;
    uint32_t size;
    uint16_t vbe_mode;
    uint16_t vbe_interface_seg;
    uint16_t vbe_interface_off;
    uint16_t vbe_interface_len;
    uint8_t vbe_control_info[512];
    uint8_t vbe_mode_info[256];
} multiboot2_tag_vbe_t;

typedef struct
{
    uint8_t red;
    uint8_t green;
    uint8_t blue;
} multiboot2_color_t;

typedef struct
{
    uint32_t type;
    uint32_t size;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint8_t framebuffer_bpp;
#define MULTIBOOT2_FRAMEBUFFER_TYPE_INDEXED  0
#define MULTIBOOT2_FRAMEBUFFER_TYPE_RGB      1
#define MULTIBOOT2_FRAMEBUFFER_TYPE_EGA_TEXT 2
    uint8_t framebuffer_type;
    uint16_t reserved;

    union
    {
        struct
        {
            uint16_t framebuffer_palette_num_colors;
            multiboot2_color_t framebuffer_palette[];
        };
        struct
        {
            uint8_t framebuffer_red_field_position;
            uint8_t framebuffer_red_mask_size;
            uint8_t framebuffer_green_field_position;
            uint8_t framebuffer_green_mask_size;
            uint8_t framebuffer_blue_field_position;
            uint8_t framebuffer_blue_mask_size;
        };
    };
} multiboot2_tag_framebuffer_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint64_t pointer;
} multiboot2_tag_efi64_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint64_t pointer;
} multiboot2_tag_efi64_ih_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t mod_start;
    uint32_t mod_end;
    char cmdline[];
} multiboot2_tag_module_t;
#endif /* __ASSEMBLY__ */

#endif /* __MULTIBOOT2_H__ */
