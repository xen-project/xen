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

struct DosFileHeader {
    UINT8   Magic[2];
    UINT16  LastSize;
    UINT16  nBlocks;
    UINT16  nReloc;
    UINT16  HdrSize;
    UINT16  MinAlloc;
    UINT16  MaxAlloc;
    UINT16  ss;
    UINT16  sp;
    UINT16  Checksum;
    UINT16  ip;
    UINT16  cs;
    UINT16  RelocPos;
    UINT16  nOverlay;
    UINT16  reserved[4];
    UINT16  OEMId;
    UINT16  OEMInfo;
    UINT16  reserved2[10];
    UINT32  ExeHeader;
};

#if defined(__arm__) || defined (__aarch64__)
#define PE_HEADER_MACHINE 0xaa64
#elif defined(__x86_64__)
#define PE_HEADER_MACHINE 0x8664
#else
#error "Unknown architecture"
#endif

struct PeFileHeader {
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
};

struct PeHeader {
    UINT8   Magic[4];
    struct PeFileHeader FileHeader;
};

struct PeSectionHeader {
    CHAR8   Name[8];
    UINT32  VirtualSize;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLinenumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
};

static bool __init pe_name_compare(const struct PeSectionHeader *sect,
                                   const CHAR16 *name)
{
    size_t i;

    if ( sect->Name[0] != '.' )
        return false;

    for ( i = 1; i < sizeof(sect->Name); i++ )
    {
        const char c = sect->Name[i];

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
    const struct DosFileHeader *dos = image;
    const struct PeHeader *pe;
    const struct PeSectionHeader *sect;
    UINTN offset, i;

    if ( image_size < sizeof(*dos) ||
         memcmp(dos->Magic, "MZ", 2) != 0 )
        return NULL;

    offset = dos->ExeHeader;
    pe = image + offset;

    offset += sizeof(*pe);
    if ( image_size < offset ||
         memcmp(pe->Magic, "PE\0\0", 4) != 0 )
        return NULL;

    if ( pe->FileHeader.Machine != PE_HEADER_MACHINE )
        return NULL;

    offset += pe->FileHeader.SizeOfOptionalHeader;

    for ( i = 0; i < pe->FileHeader.NumberOfSections; i++ )
    {
        sect = image + offset;
        if ( image_size < offset + sizeof(*sect) )
            return NULL;

        if ( !pe_name_compare(sect, section_name) )
        {
            offset += sizeof(*sect);
            continue;
        }

        if ( image_size < sect->VirtualSize + sect->VirtualAddress )
            blexit(L"PE invalid section size + address");

        if ( size_out )
            *size_out = sect->VirtualSize;

        return image + sect->VirtualAddress;
    }

    return NULL;
}
