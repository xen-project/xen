#include <asm/privop_stat.h>
#include <asm/vhpt.h>
#include <xen/lib.h>
#include <asm/uaccess.h>

unsigned long slow_hyperpriv_cnt[HYPERPRIVOP_MAX+1] = { 0 };
unsigned long fast_hyperpriv_cnt[HYPERPRIVOP_MAX+1] = { 0 };

unsigned long slow_reflect_count[0x80] = { 0 };
unsigned long fast_reflect_count[0x80] = { 0 };

struct privop_counters privcnt;

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

// FIXME: should use snprintf to ensure no buffer overflow
static int dump_privop_counts(char *buf)
{
	int i, j;
	unsigned long sum = 0;
	char *s = buf;

	// this is ugly and should probably produce sorted output
	// but it will have to do for now
	sum += privcnt.mov_to_ar_imm; sum += privcnt.mov_to_ar_reg;
	sum += privcnt.ssm; sum += privcnt.rsm;
	sum += privcnt.rfi; sum += privcnt.bsw0;
	sum += privcnt.bsw1; sum += privcnt.cover;
	for (i=0; i < 64; i++)
		sum += privcnt.Mpriv_cnt[i];
	s += sprintf(s,"Privop statistics: (Total privops: %ld)\n",sum);
	if (privcnt.mov_to_ar_imm)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.mov_to_ar_imm,
			"mov_to_ar_imm", (privcnt.mov_to_ar_imm*100L)/sum);
	if (privcnt.mov_to_ar_reg)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.mov_to_ar_reg,
			"mov_to_ar_reg", (privcnt.mov_to_ar_reg*100L)/sum);
	if (privcnt.mov_from_ar)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.mov_from_ar,
			"privified-mov_from_ar", (privcnt.mov_from_ar*100L)/sum);
	if (privcnt.ssm)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.ssm,
			"ssm", (privcnt.ssm*100L)/sum);
	if (privcnt.rsm)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.rsm,
			"rsm", (privcnt.rsm*100L)/sum);
	if (privcnt.rfi)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.rfi,
			"rfi", (privcnt.rfi*100L)/sum);
	if (privcnt.bsw0)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.bsw0,
			"bsw0", (privcnt.bsw0*100L)/sum);
	if (privcnt.bsw1)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.bsw1,
			"bsw1", (privcnt.bsw1*100L)/sum);
	if (privcnt.cover)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.cover,
			"cover", (privcnt.cover*100L)/sum);
	if (privcnt.fc)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.fc,
			"privified-fc", (privcnt.fc*100L)/sum);
	if (privcnt.cpuid)
		s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.cpuid,
			"privified-getcpuid", (privcnt.cpuid*100L)/sum);
	for (i=0; i < 64; i++) if (privcnt.Mpriv_cnt[i]) {
		if (!Mpriv_str[i]) s += sprintf(s,"PRIVSTRING NULL!!\n");
		else s += sprintf(s,"%10ld  %s [%ld%%]\n", privcnt.Mpriv_cnt[i],
			Mpriv_str[i], (privcnt.Mpriv_cnt[i]*100L)/sum);
		if (i == 0x24) { // mov from CR
			s += sprintf(s,"            [");
			for (j=0; j < 128; j++) if (privcnt.from_cr_cnt[j]) {
				if (!cr_str[j])
					s += sprintf(s,"PRIVSTRING NULL!!\n");
				else
					s += sprintf(s,"%s(%ld),",cr_str[j],
						     privcnt.from_cr_cnt[j]);
			}
			s += sprintf(s,"]\n");
		}
		else if (i == 0x2c) { // mov to CR
			s += sprintf(s,"            [");
			for (j=0; j < 128; j++) if (privcnt.to_cr_cnt[j]) {
				if (!cr_str[j])
					s += sprintf(s,"PRIVSTRING NULL!!\n");
				else
					s += sprintf(s,"%s(%ld),",cr_str[j],
						     privcnt.to_cr_cnt[j]);
			}
			s += sprintf(s,"]\n");
		}
	}
	return s - buf;
}

static int zero_privop_counts(char *buf)
{
	int i, j;
	char *s = buf;

	// this is ugly and should probably produce sorted output
	// but it will have to do for now
	privcnt.mov_to_ar_imm = 0;
	privcnt.mov_to_ar_reg = 0;
	privcnt.mov_from_ar = 0;
	privcnt.ssm = 0; privcnt.rsm = 0;
	privcnt.rfi = 0; privcnt.bsw0 = 0;
	privcnt.bsw1 = 0; privcnt.cover = 0;
	privcnt.fc = 0; privcnt.cpuid = 0;
	for (i=0; i < 64; i++)
		privcnt.Mpriv_cnt[i] = 0;
	for (j=0; j < 128; j++)
		privcnt.from_cr_cnt[j] = 0;
	for (j=0; j < 128; j++)
		privcnt.to_cr_cnt[j] = 0;
	s += sprintf(s,"All privop statistics zeroed\n");
	return s - buf;
}

static const char * const hyperpriv_str[HYPERPRIVOP_MAX+1] = {
	0, "rfi", "rsm.dt", "ssm.dt", "cover", "itc.d", "itc.i", "ssm.i",
	"=ivr", "=tpr", "tpr=", "eoi", "itm=", "thash", "ptc.ga", "itr.d",
	"=rr", "rr=", "kr=", "fc", "=cpuid", "=pmd", "=ar.eflg", "ar.eflg="
};


static int dump_hyperprivop_counts(char *buf)
{
	int i;
	char *s = buf;
	unsigned long total = 0;
	for (i = 1; i <= HYPERPRIVOP_MAX; i++)
		total += slow_hyperpriv_cnt[i];
	s += sprintf(s,"Slow hyperprivops (total %ld):\n",total);
	for (i = 1; i <= HYPERPRIVOP_MAX; i++)
		if (slow_hyperpriv_cnt[i])
			s += sprintf(s,"%10ld %s\n",
				slow_hyperpriv_cnt[i], hyperpriv_str[i]);
	total = 0;
	for (i = 1; i <= HYPERPRIVOP_MAX; i++)
		total += fast_hyperpriv_cnt[i];
	s += sprintf(s,"Fast hyperprivops (total %ld):\n",total);
	for (i = 1; i <= HYPERPRIVOP_MAX; i++)
		if (fast_hyperpriv_cnt[i])
			s += sprintf(s,"%10ld %s\n",
				fast_hyperpriv_cnt[i], hyperpriv_str[i]);
	return s - buf;
}

static void zero_hyperprivop_counts(void)
{
	int i;
	for (i = 0; i <= HYPERPRIVOP_MAX; i++)
		slow_hyperpriv_cnt[i] = 0;
	for (i = 0; i <= HYPERPRIVOP_MAX; i++)
		fast_hyperpriv_cnt[i] = 0;
}

static void zero_reflect_counts(void)
{
	int i;
	for (i=0; i < 0x80; i++)
		slow_reflect_count[i] = 0;
	for (i=0; i < 0x80; i++)
		fast_reflect_count[i] = 0;
}

static int dump_reflect_counts(char *buf)
{
	int i,j,cnt;
	char *s = buf;

	s += sprintf(s,"Slow reflections by vector:\n");
	for (i = 0, j = 0; i < 0x80; i++) {
		if ( (cnt = slow_reflect_count[i]) != 0 ) {
			s += sprintf(s,"0x%02x00:%10d, ",i,cnt);
			if ((j++ & 3) == 3)
				s += sprintf(s,"\n");
		}
	}
	if (j & 3)
		s += sprintf(s,"\n");
	s += sprintf(s,"Fast reflections by vector:\n");
	for (i = 0, j = 0; i < 0x80; i++) {
		if ( (cnt = fast_reflect_count[i]) != 0 ) {
			s += sprintf(s,"0x%02x00:%10d, ",i,cnt);
			if ((j++ & 3) == 3)
				s += sprintf(s,"\n");
		}
	}
	if (j & 3)
		s += sprintf(s,"\n");
	return s - buf;
}


#define TMPBUFLEN 8*1024
int dump_privop_counts_to_user(char __user *ubuf, int len)
{
	char buf[TMPBUFLEN];
	int n;

	if (len < TMPBUFLEN)
		return -1;

	n = dump_privop_counts(buf);
	n += dump_hyperprivop_counts(buf + n);
	n += dump_reflect_counts(buf + n);
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
	char buf[TMPBUFLEN];
	int n;

	if (len < TMPBUFLEN)
		return -1;

	n = zero_privop_counts(buf);

	zero_hyperprivop_counts();
#ifdef PRIVOP_ADDR_COUNT
	zero_privop_addrs();
#endif
	zero_vhpt_stats();
	zero_reflect_counts();
	if (__copy_to_user(ubuf,buf,n))
		return -1;
	return n;
}
