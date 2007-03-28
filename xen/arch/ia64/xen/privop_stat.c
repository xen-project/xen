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
};

struct privop_addr_info {
	enum perfcounter perfc_addr;
	enum perfcounter perfc_count;
	enum perfcounter perfc_overflow;
};

#define PERFCOUNTER(var, name)
#define PERFCOUNTER_ARRAY(var, name, size)

#define PERFSTATUS(var, name)
#define PERFSTATUS_ARRAY(var, name, size)

#define PERFPRIVOPADDR(name)                        \
    {                                               \
        PERFC_privop_addr_##name##_addr,            \
        PERFC_privop_addr_##name##_count,           \
        PERFC_privop_addr_##name##_overflow         \
    },

static const struct privop_addr_info privop_addr_info[] = {
#include <asm/perfc_defn.h>
};

#define PRIVOP_COUNT_NINSTS \
        (sizeof(privop_addr_info) / sizeof(privop_addr_info[0]))

static DEFINE_PER_CPU(struct privop_addr_count[PRIVOP_COUNT_NINSTS], privop_addr_counter);

void privop_count_addr(unsigned long iip, enum privop_inst inst)
{
	struct privop_addr_count *v = this_cpu(privop_addr_counter) + inst;
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
	unsigned int cpu;

	for_each_cpu ( cpu ) {
		perfc_t *perfcounters = per_cpu(perfcounters, cpu);
		struct privop_addr_count *s = per_cpu(privop_addr_counter, cpu);
		int i, j;

		for (i = 0; i < PRIVOP_COUNT_NINSTS; i++, s++) {
			perfc_t *d;

			/* Note: addresses are truncated!  */
			d = perfcounters + privop_addr_info[i].perfc_addr;
			for (j = 0; j < PRIVOP_COUNT_NADDRS; j++)
				d[j] = s->addr[j];

			d = perfcounters + privop_addr_info[i].perfc_count;
			for (j = 0; j < PRIVOP_COUNT_NADDRS; j++)
				d[j] = s->count[j];
		
			perfcounters[privop_addr_info[i].perfc_overflow] =
				s->overflow;
		}
	}
}

void reset_privop_addrs(void)
{
	unsigned int cpu;

	for_each_cpu ( cpu ) {
		struct privop_addr_count *v = per_cpu(privop_addr_counter, cpu);
		int i, j;

		for (i = 0; i < PRIVOP_COUNT_NINSTS; i++, v++) {
			for (j = 0; j < PRIVOP_COUNT_NADDRS; j++)
				v->addr[j] = v->count[j] = 0;
			v->overflow = 0;
		}
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
