
#ifndef __DEBUGGER_HOOKS_H__
#define __DEBUGGER_HOOKS_H__

static inline int debugger_trap(int type, struct xen_regs *regs)
{
    int ret = 0;

#ifdef XEN_DEBUGGER
    switch (type) {
    case 3:
        if ( pdb_initialized && pdb_handle_exception(type, regs) == 0 )
            return 1;
        break;
    case 14:
        if ( pdb_page_fault_possible )
        {
            pdb_page_fault = 1;
            /* make eax & edx valid to complete the instruction */
            regs->eax = (long)&pdb_page_fault_scratch;
            regs->edx = (long)&pdb_page_fault_scratch;
            return 1;
        }
        break;
    }
#endif

#if 0
    extern int kdb_trap(int, int, struct xen_regs *);
    if ((ret = kdb_trap(type, 0, regs)))
        return ret;
#endif

    return ret;
}

#endif /* __DEBUGGER_HOOKS_H__ */
