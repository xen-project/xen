#include <xen/lib.h>
#include <public/xen.h>
#include <xen/perfc.h>
#include <asm/atomic.h>
#include <asm/privop_stat.h>

#ifdef CONFIG_PRIVOP_ADDRS

struct privop_addr_count {
	unsigned long addr[PRIVOP_COUNT_NADDRS];
	unsigned int count[PRIVOP_COUNT_NADDRS];
	unsigned int overflow;
	atomic_t *perfc_addr;
	atomic_t *perfc_count;
	atomic_t *perfc_overflow;
};

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

#undef PERFPRIVOPADDR
#define PERFPRIVOPADDR(name)                        \
    {                                               \
        { 0 }, { 0 }, 0,                            \
        perfcounters.privop_addr_##name##_addr,     \
        perfcounters.privop_addr_##name##_count,    \
        perfcounters.privop_addr_##name##_overflow  \
    },

static struct privop_addr_count privop_addr_counter[] = {
#include <asm/perfc_defn.h>
};

#define PRIVOP_COUNT_NINSTS \
        (sizeof(privop_addr_counter) / sizeof(privop_addr_counter[0]))

void privop_count_addr(unsigned long iip, enum privop_inst inst)
{
	struct privop_addr_count *v = &privop_addr_counter[inst];
	int i;

	if (inst >= PRIVOP_COUNT_NINSTS)
		return;
	for (i = 0; i < PRIVOP_COUNT_NADDRS; i++) {
		if (!v->addr[i]) {
			v->addr[i] = iip;
			v->count[i]++;
			return;
		}
		else if (v->addr[i] == iip) {
			v->count[i]++;
			return;
		}
	}
	v->overflow++;;
}

void gather_privop_addrs(void)
{
	int i, j;
	atomic_t *v;
	for (i = 0; i < PRIVOP_COUNT_NINSTS; i++) {
		/* Note: addresses are truncated!  */
		v = privop_addr_counter[i].perfc_addr;
		for (j = 0; j < PRIVOP_COUNT_NADDRS; j++)
			atomic_set(&v[j], privop_addr_counter[i].addr[j]);

		v = privop_addr_counter[i].perfc_count;
		for (j = 0; j < PRIVOP_COUNT_NADDRS; j++)
			atomic_set(&v[j], privop_addr_counter[i].count[j]);
		
		atomic_set(privop_addr_counter[i].perfc_overflow,
		           privop_addr_counter[i].overflow);
	}
}

void reset_privop_addrs(void)
{
	int i, j;
	for (i = 0; i < PRIVOP_COUNT_NINSTS; i++) {
		struct privop_addr_count *v = &privop_addr_counter[i];
		for (j = 0; j < PRIVOP_COUNT_NADDRS; j++)
			v->addr[j] = v->count[j] = 0;
		v->overflow = 0;
	}
}
#endif

/**************************************************************************
Privileged operation instrumentation routines
**************************************************************************/

#if 0
static const char * const Mpriv_str[64] = {
	"mov_to_rr", "mov_to_dbr", "mov_to_ibr", "mov_to_pkr",
	"mov_to_pmc", "mov_to_pmd", "<0x06>", "<0x07>",
	"<0x08>", "ptc_l", "ptc_g", "ptc_ga",
	"ptr_d", "ptr_i", "itr_d", "itr_i",
	"mov_from_rr", "mov_from_dbr", "mov_from_ibr", "mov_from_pkr",
	"mov_from_pmc", "<0x15>", "<0x16>", "<0x17>",
	"<0x18>", "<0x19>", "privified-thash", "privified-ttag",
	"<0x1c>", "<0x1d>", "tpa", "tak",
	"<0x20>", "<0x21>", "<0x22>", "<0x23>",
	"mov_from_cr", "mov_from_psr", "<0x26>", "<0x27>",
	"<0x28>", "<0x29>", "<0x2a>", "<0x2b>",
	"mov_to_cr", "mov_to_psr", "itc_d", "itc_i",
	"<0x30>", "<0x31>", "<0x32>", "<0x33>",
	"ptc_e", "<0x35>", "<0x36>", "<0x37>",
	"<0x38>", "<0x39>", "<0x3a>", "<0x3b>",
	"<0x3c>", "<0x3d>", "<0x3e>", "<0x3f>"
};

#define RS "Rsvd"
static const char * const cr_str[128] = {
	"dcr","itm","iva",RS,RS,RS,RS,RS,
	"pta",RS,RS,RS,RS,RS,RS,RS,
	"ipsr","isr",RS,"iip","ifa","itir","iipa","ifs",
	"iim","iha",RS,RS,RS,RS,RS,RS,
	RS,RS,RS,RS,RS,RS,RS,RS, RS,RS,RS,RS,RS,RS,RS,RS,
	RS,RS,RS,RS,RS,RS,RS,RS, RS,RS,RS,RS,RS,RS,RS,RS,
	"lid","ivr","tpr","eoi","irr0","irr1","irr2","irr3",
	"itv","pmv","cmcv",RS,RS,RS,RS,RS,
	"lrr0","lrr1",RS,RS,RS,RS,RS,RS,
	RS,RS,RS,RS,RS,RS,RS,RS, RS,RS,RS,RS,RS,RS,RS,RS,
	RS,RS,RS,RS,RS,RS,RS,RS, RS,RS,RS,RS,RS,RS,RS,RS,
	RS,RS,RS,RS,RS,RS,RS,RS
};

static const char * const hyperpriv_str[HYPERPRIVOP_MAX+1] = {
	0, "rfi", "rsm.dt", "ssm.dt", "cover", "itc.d", "itc.i", "ssm.i",
	"=ivr", "=tpr", "tpr=", "eoi", "itm=", "thash", "ptc.ga", "itr.d",
	"=rr", "rr=", "kr=", "fc", "=cpuid", "=pmd", "=ar.eflg", "ar.eflg="
};
#endif
