#include <xen/sched.h>

#include <asm/pv/trace.h>

void __trace_pv_trap(int trapnr, unsigned long eip,
                     int use_error_code, unsigned error_code)
{
    if ( is_pv_32bit_vcpu(current) )
    {
        struct {
            uint32_t eip;
            uint16_t trapnr:15;
            bool use_error_code:1;
            uint16_t error_code;
        } d = {
            .eip            = eip,
            .trapnr         = trapnr,
            .use_error_code = use_error_code,
            .error_code     = error_code,
        };

        trace_time(TRC_PV_TRAP, sizeof(d), &d);
    }
    else
    {
        struct __packed {
            uint64_t rip;
            uint16_t trapnr:15;
            bool use_error_code:1;
            uint16_t error_code;
        } d = {
            .rip            = eip,
            .trapnr         = trapnr,
            .use_error_code = use_error_code,
            .error_code     = error_code,
        };

        trace_time(TRC_PV_TRAP | TRC_64_FLAG, sizeof(d), &d);
    }
}

void __trace_pv_page_fault(unsigned long addr, unsigned error_code)
{
    unsigned long eip = guest_cpu_user_regs()->rip;

    if ( is_pv_32bit_vcpu(current) )
    {
        struct {
            uint32_t eip, addr, error_code;
        } d = {
            .eip        = eip,
            .addr       = addr,
            .error_code = error_code,
        };

        trace_time(TRC_PV_PAGE_FAULT, sizeof(d), &d);
    }
    else
    {
        struct __packed {
            uint64_t rip, addr;
            uint32_t error_code;
        } d = {
            .rip        = eip,
            .addr       = addr,
            .error_code = error_code,
        };

        trace_time(TRC_PV_PAGE_FAULT | TRC_64_FLAG, sizeof(d), &d);
    }
}

void __trace_trap_one_addr(unsigned event, unsigned long va)
{
    if ( is_pv_32bit_vcpu(current) )
    {
        u32 d = va;

        trace_time(event, sizeof(d), &d);
    }
    else
        trace_time(event | TRC_64_FLAG, sizeof(va), &va);
}

void __trace_trap_two_addr(unsigned event, unsigned long va1,
                           unsigned long va2)
{
    if ( is_pv_32bit_vcpu(current) )
    {
        struct {
            uint32_t va1, va2;
        } d = {
            .va1 = va1,
            .va2 = va2,
        };

        trace_time(event, sizeof(d), &d);
    }
    else
    {
        struct {
            uint64_t va1, va2;
        } d = {
            .va1 = va1,
            .va2 = va2,
        };

        trace_time(event | TRC_64_FLAG, sizeof(d), &d);
    }
}

void __trace_ptwr_emulation(unsigned long addr, l1_pgentry_t npte)
{
    unsigned long eip = guest_cpu_user_regs()->rip;

    if ( is_pv_32bit_vcpu(current) )
    {
        struct {
            uint64_t pte;
            uint32_t addr, eip;
        } d = {
            .pte  = l1e_get_intpte(npte),
            .addr = addr,
            .eip  = eip,
        };

        trace_time(TRC_PV_PTWR_EMULATION_PAE, sizeof(d), &d);
    }
    else
    {
        struct {
            uint64_t pte;
            uint64_t addr, rip;
        } d = {
            .pte  = l1e_get_intpte(npte),
            .addr = addr,
            .rip  = eip,
        };

        trace_time(TRC_PV_PTWR_EMULATION | TRC_64_FLAG, sizeof(d), &d);
    }
}
