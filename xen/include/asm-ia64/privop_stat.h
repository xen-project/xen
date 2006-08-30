#ifndef _XEN_UA64_PRIVOP_STAT_H
#define _XEN_UA64_PRIVOP_STAT_H
#include <asm/config.h>
#include <xen/types.h>
#include <public/xen.h>

#ifdef CONFIG_PRIVOP_ADDRS

extern void gather_privop_addrs(void);
extern void reset_privop_addrs(void);

#undef  PERFCOUNTER
#define PERFCOUNTER(var, name)

#undef  PERFCOUNTER_CPU
#define PERFCOUNTER_CPU(var, name)

#undef  PERFCOUNTER_ARRAY
#define PERFCOUNTER_ARRAY(var, name, size)

#undef  PERFSTATUS
#define PERFSTATUS(var, name)

#undef  PERFSTATUS_CPU
#define PERFSTATUS_CPU(var, name)

#undef  PERFSTATUS_ARRAY
#define PERFSTATUS_ARRAY(var, name, size)

#undef  PERFPRIVOPADDR
#define PERFPRIVOPADDR(name) privop_inst_##name,

enum privop_inst {
#include <asm/perfc_defn.h>
};

#undef PERFPRIVOPADDR

#define	PRIVOP_COUNT_ADDR(regs,inst) privop_count_addr(regs->cr_iip,inst)
extern void privop_count_addr(unsigned long addr, enum privop_inst inst);

#else
#define PRIVOP_COUNT_ADDR(x,y) do {} while (0)
#define gather_privop_addrs() do {} while (0)
#define reset_privop_addrs() do {} while (0)
#endif

#endif /* _XEN_UA64_PRIVOP_STAT_H */
