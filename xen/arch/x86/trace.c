#include <xen/config.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/domain.h>
#include <xen/sched.h>
#include <xen/trace.h>

void __trace_pv_trap(int trapnr, unsigned long eip,
                     int use_error_code, unsigned error_code)
{
    if ( is_pv_32bit_vcpu(current) )
    {
        struct __packed {
            unsigned eip:32,
                trapnr:15,
                use_error_code:1,
                error_code:16;
        } d;

        d.eip = eip;
        d.trapnr = trapnr;
        d.error_code = error_code;
        d.use_error_code=!!use_error_code;
                
        __trace_var(TRC_PV_TRAP, 1, sizeof(d), &d);
    }
    else
    {
        struct __packed {
            unsigned long eip;
            unsigned trapnr:15,
                use_error_code:1,
                error_code:16;
        } d;
        unsigned event;

        d.eip = eip;
        d.trapnr = trapnr;
        d.error_code = error_code;
        d.use_error_code=!!use_error_code;
                
        event = TRC_PV_TRAP;
        event |= TRC_64_FLAG;
        __trace_var(event, 1, sizeof(d), &d);
    }
}

void __trace_pv_page_fault(unsigned long addr, unsigned error_code)
{
    unsigned long eip = guest_cpu_user_regs()->eip;

    if ( is_pv_32bit_vcpu(current) )
    {
        struct __packed {
            u32 eip, addr, error_code;
        } d;

        d.eip = eip;
        d.addr = addr;
        d.error_code = error_code;
                
        __trace_var(TRC_PV_PAGE_FAULT, 1, sizeof(d), &d);
    }
    else
    {
        struct __packed {
            unsigned long eip, addr;
            u32 error_code;
        } d;
        unsigned event;

        d.eip = eip;
        d.addr = addr;
        d.error_code = error_code;
        event = TRC_PV_PAGE_FAULT;
        event |= TRC_64_FLAG;
        __trace_var(event, 1, sizeof(d), &d);
    }
}

void __trace_trap_one_addr(unsigned event, unsigned long va)
{
    if ( is_pv_32bit_vcpu(current) )
    {
        u32 d = va;
        __trace_var(event, 1, sizeof(d), &d);
    }
    else
    {
        event |= TRC_64_FLAG;
        __trace_var(event, 1, sizeof(va), &va);
    }
}

void __trace_trap_two_addr(unsigned event, unsigned long va1,
                           unsigned long va2)
{
    if ( is_pv_32bit_vcpu(current) )
    {
        struct __packed {
            u32 va1, va2;
        } d;
        d.va1=va1;
        d.va2=va2;
        __trace_var(event, 1, sizeof(d), &d);
    }
    else
    {
        struct __packed {
            unsigned long va1, va2;
        } d;
        d.va1=va1;
        d.va2=va2;
        event |= TRC_64_FLAG;
        __trace_var(event, 1, sizeof(d), &d);
    }
}

void __trace_ptwr_emulation(unsigned long addr, l1_pgentry_t npte)
{
    unsigned long eip = guest_cpu_user_regs()->eip;

    /* We have a couple of different modes to worry about:
     * - 32-on-32: 32-bit pte, 32-bit virtual addresses
     * - pae-on-pae, pae-on-64: 64-bit pte, 32-bit virtual addresses
     * - 64-on-64: 64-bit pte, 64-bit virtual addresses
     * pae-on-64 is the only one that requires extra code; in all other
     * cases, "unsigned long" is the size of a guest virtual address.
     */

    if ( is_pv_32bit_vcpu(current) )
    {
        struct __packed {
            l1_pgentry_t pte;
            u32 addr, eip;
        } d;
        d.addr = addr;
        d.eip = eip;
        d.pte = npte;

        __trace_var(TRC_PV_PTWR_EMULATION_PAE, 1, sizeof(d), &d);
    }
    else
    {
        struct {
            l1_pgentry_t pte;
            unsigned long addr, eip;
        } d;
        unsigned event;

        d.addr = addr;
        d.eip = eip;
        d.pte = npte;

        event = TRC_PV_PTWR_EMULATION;
        event |= TRC_64_FLAG;
        __trace_var(event, 1/*tsc*/, sizeof(d), &d);
    }
}
