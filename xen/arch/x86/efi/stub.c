#include <xen/efi.h>
#include <xen/init.h>
#include <asm/asm_defns.h>
#include <asm/efibind.h>
#include <asm/page.h>
#include <efi/efidef.h>
#include <efi/eficapsule.h>
#include <efi/eficon.h>
#include <efi/efidevp.h>
#include <efi/efiapi.h>
#include "../../../common/efi/stub.c"

/*
 * Here we are in EFI stub. EFI calls are not supported due to lack
 * of relevant functionality in compiler and/or linker.
 *
 * efi_multiboot2() is an exception. Please look below for more details.
 */

void __init noreturn efi_multiboot2(EFI_HANDLE ImageHandle,
                                    EFI_SYSTEM_TABLE *SystemTable)
{
    static const CHAR16 __initconst err[] =
        L"Xen does not have EFI code build in!\r\nSystem halted!\r\n";
    SIMPLE_TEXT_OUTPUT_INTERFACE *StdErr;

    StdErr = SystemTable->StdErr ? SystemTable->StdErr : SystemTable->ConOut;

    /*
     * Print error message and halt the system.
     *
     * We have to open code MS x64 calling convention
     * in assembly because here this convention may
     * not be directly supported by C compiler.
     */
    asm volatile(
    "    call *%[outstr]              \n"
    "0:  hlt                          \n"
    "    jmp  0b                      \n"
       : "+c" (StdErr), "=d" (StdErr) ASM_CALL_CONSTRAINT
       : "1" (err), [outstr] "rm" (StdErr->OutputString)
       : "rax", "r8", "r9", "r10", "r11", "memory");

    unreachable();
}

void __init efi_init_memory(void) { }

bool efi_boot_mem_unused(unsigned long *start, unsigned long *end)
{
    /* FIXME: Simplify once the call here with two NULLs goes away. */
    if ( start || end )
        *start = *end = (unsigned long)_end;
    return false;
}

void efi_update_l4_pgtable(unsigned int l4idx, l4_pgentry_t l4e) { }

int efi_compat_get_info(uint32_t idx, union compat_pf_efi_info *)
    __attribute__((__alias__("efi_get_info")));

int efi_compat_runtime_call(struct compat_pf_efi_runtime_call *)
    __attribute__((__alias__("efi_runtime_call")));
