#include <xen/efi.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <asm/page.h>
#include <asm/efibind.h>
#include <efi/efidef.h>
#include <efi/eficapsule.h>
#include <efi/eficon.h>
#include <efi/efidevp.h>
#include <efi/efiapi.h>

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
    "    call *%3                     \n"
    "0:  hlt                          \n"
    "    jmp  0b                      \n"
       : "+c" (StdErr), "=d" (StdErr) : "1" (err), "rm" (StdErr->OutputString)
       : "rax", "r8", "r9", "r10", "r11", "memory");

    unreachable();
}

bool efi_enabled(unsigned int feature)
{
    return false;
}

void __init efi_init_memory(void) { }

void efi_update_l4_pgtable(unsigned int l4idx, l4_pgentry_t l4e) { }

bool efi_rs_using_pgtables(void)
{
    return false;
}

unsigned long efi_get_time(void)
{
    BUG();
    return 0;
}

void efi_halt_system(void) { }
void efi_reset_system(bool warm) { }

int efi_get_info(uint32_t idx, union xenpf_efi_info *info)
{
    return -ENOSYS;
}

int efi_compat_get_info(uint32_t idx, union compat_pf_efi_info *)
    __attribute__((__alias__("efi_get_info")));

int efi_runtime_call(struct xenpf_efi_runtime_call *op)
{
    return -ENOSYS;
}

int efi_compat_runtime_call(struct compat_pf_efi_runtime_call *)
    __attribute__((__alias__("efi_runtime_call")));
