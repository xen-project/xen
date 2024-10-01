/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef X86_ASM_EFI_H
#define X86_ASM_EFI_H

#include <xen/types.h>
#include <asm/x86_64/efibind.h>
#include <efi/efidef.h>
#include <efi/eficapsule.h>
#include <efi/eficon.h>
#include <efi/efidevp.h>
#include <efi/efiapi.h>

void efi_multiboot2(EFI_HANDLE ImageHandle,
                    EFI_SYSTEM_TABLE *SystemTable,
                    const char *cmdline);

#endif /* X86_ASM_EFI_H */
