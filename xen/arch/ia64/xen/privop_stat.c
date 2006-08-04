#include <asm/privop_stat.h>
#include <asm/vhpt.h>
#include <xen/lib.h>
#include <asm/uaccess.h>

#ifdef PRIVOP_ADDR_COUNT
#define PRIVOP_COUNT_NINSTS 2
#define PRIVOP_COUNT_NADDRS 30

struct privop_addr_count {
	const char *instname;
	unsigned long addr[PRIVOP_COUNT_NADDRS];
	unsigned long count[PRIVOP_COUNT_NADDRS];
	unsigned long overflow;
};


static struct privop_addr_count privop_addr_counter[PRIVOP_COUNT_NINSTS] = {
	[_GET_IFA] = { "=ifa",  { 0 }, { 0 }, 0 },
	[_THASH] = { "thash", { 0 }, { 0 }, 0 }
};

void privop_count_addr(unsigned long iip, int inst)
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

static int dump_privop_addrs(char *buf)
{
	int i, j;
	char *s = buf;
	s += sprintf(s, "Privop addresses:\n");
	for (i = 0; i < PRIVOP_COUNT_NINSTS; i++) {
		struct privop_addr_count *v = &privop_addr_counter[i];
		s += sprintf(s, "%s:\n", v->instname);
		for (j = 0; j < PRIVOP_COUNT_NADDRS; j++) {
			if (!v->addr[j])
				break;
			s += sprintf(s, " at 0x%lx #%ld\n",
			             v->addr[j], v->count[j]);
		}
		if (v->overflow) 
			s += sprintf(s, " other #%ld\n", v->overflow);
	}
	return s - buf;
}

static void zero_privop_addrs(void)
{
	int i,j;
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

#define TMPBUFLEN 8*1024
int dump_privop_counts_to_user(char __user *ubuf, int len)
{
	char buf[TMPBUFLEN];
	int n;

	if (len < TMPBUFLEN)
		return -1;

	n = 0;
#ifdef PRIVOP_ADDR_COUNT
	n += dump_privop_addrs(buf + n);
#endif
	n += dump_vhpt_stats(buf + n);
	if (__copy_to_user(ubuf,buf,n))
		return -1;
	return n;
}

int zero_privop_counts_to_user(char __user *ubuf, int len)
{
#ifdef PRIVOP_ADDR_COUNT
	zero_privop_addrs();
#endif
	return 0;
}
