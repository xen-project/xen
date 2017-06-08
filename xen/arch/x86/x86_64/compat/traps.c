#include <xen/event.h>
#include <asm/regs.h>
#include <compat/callback.h>
#include <compat/arch-x86_32.h>

int compat_set_trap_table(XEN_GUEST_HANDLE(trap_info_compat_t) traps)
{
    struct compat_trap_info cur;
    struct trap_info *dst = current->arch.pv_vcpu.trap_ctxt;
    long rc = 0;

    /* If no table is presented then clear the entire virtual IDT. */
    if ( guest_handle_is_null(traps) )
    {
        memset(dst, 0, NR_VECTORS * sizeof(*dst));
        init_int80_direct_trap(current);
        return 0;
    }

    for ( ; ; )
    {
        if ( copy_from_guest(&cur, traps, 1) )
        {
            rc = -EFAULT;
            break;
        }

        if ( cur.address == 0 )
            break;

        fixup_guest_code_selector(current->domain, cur.cs);

        XLAT_trap_info(dst + cur.vector, &cur);

        if ( cur.vector == 0x80 )
            init_int80_direct_trap(current);

        guest_handle_add_offset(traps, 1);

        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_set_trap_table, "h", traps);
            break;
        }
    }

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
