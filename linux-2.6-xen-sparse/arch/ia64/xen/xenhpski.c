
extern unsigned long xen_get_cpuid(int);

int
running_on_sim(void)
{
	int i;
	long cpuid[6];

	for (i = 0; i < 5; ++i)
		cpuid[i] = xen_get_cpuid(i);
	if ((cpuid[0] & 0xff) != 'H') return 0;
	if ((cpuid[3] & 0xff) != 0x4) return 0;
	if (((cpuid[3] >> 8) & 0xff) != 0x0) return 0;
	if (((cpuid[3] >> 16) & 0xff) != 0x0) return 0;
	if (((cpuid[3] >> 24) & 0x7) != 0x7) return 0;
	return 1;
}

