/*
 * xen/common/efi/pe.c
 *
 * PE executable header parser.
 *
 * Derived from https://github.com/systemd/systemd/blob/master/src/boot/efi/pe.c
 * commit 07d5ed536ec0a76b08229c7a80b910cb9acaf6b1
 *
 * Copyright (C) 2015 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2020 Trammell Hudson <hudson@trmm.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

#include "efi.h"
#include "efi/pe.h"

#if defined(__arm__) || defined (__aarch64__)
#define PE_HEADER_MACHINE 0xaa64
#elif defined(__x86_64__)
#define PE_HEADER_MACHINE 0x8664
#else
#error "Unknown architecture"
#endif

static bool __init pe_name_compare(const struct section_header *sect,
                                   const CHAR16 *name)
{
    size_t i;

    if ( sect->name[0] != '.' )
        return false;

    for ( i = 1; i < sizeof(sect->name); i++ )
    {
        const char c = sect->name[i];

        if ( c != name[i - 1] )
            return false;
        if ( c == '\0' )
            return true;
    }

    return name[i - 1] == L'\0';
}

const void *__init pe_find_section(const void *image, const UINTN image_size,
                                   const CHAR16 *section_name, UINTN *size_out)
{
    const struct mz_hdr *mz = image;
    const struct pe_hdr *pe;
    const struct section_header *sect;
    UINTN offset, i;

    if ( image_size < sizeof(*mz) ||
         mz->magic != MZ_MAGIC )
        return NULL;

    offset = mz->peaddr;
    pe = image + offset;

    offset += sizeof(*pe);
    if ( image_size < offset ||
         pe->magic != PE_MAGIC )
        return NULL;

    if ( pe->machine != PE_HEADER_MACHINE )
        return NULL;

    offset += pe->opt_hdr_size;

    for ( i = 0; i < pe->sections; i++ )
    {
        sect = image + offset;
        if ( image_size < offset + sizeof(*sect) )
            return NULL;

        if ( !pe_name_compare(sect, section_name) )
        {
            offset += sizeof(*sect);
            continue;
        }

        if ( image_size < sect->virtual_size + sect->rva )
            blexit(L"PE invalid section size + address");

        if ( size_out )
            *size_out = sect->virtual_size;

        return image + sect->rva;
    }

    return NULL;
}
