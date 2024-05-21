#include <xen/bug.h>

struct vm_event_st;
struct vcpu;

void vm_event_fill_regs(struct vm_event_st *req)
{
    BUG_ON("unimplemented");
}

void vm_event_set_registers(struct vcpu *v, struct vm_event_st *rsp)
{
    BUG_ON("unimplemented");
}

void vm_event_monitor_next_interrupt(struct vcpu *v)
{
    /* Not supported on RISCV. */
}
