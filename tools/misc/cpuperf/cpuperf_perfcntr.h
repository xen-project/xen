/*
 * Interface to JRB44's /proc/perfcntr interface.
 *
 * $Id: cpuperf_perfcntr.h,v 1.1 2003/10/13 16:49:44 jrb44 Exp $
 *
 * $Log: cpuperf_perfcntr.h,v $
 * Revision 1.1  2003/10/13 16:49:44  jrb44
 * Initial revision
 *
 */

#define  PROC_PERFCNTR "/proc/perfcntr"

static inline void perfcntr_wrmsr(int cpu_mask,
                                  int msr,
                                  unsigned int low,
                                  unsigned int high )
{
    FILE *fd;
    unsigned long long value = low | (((unsigned long long)high) << 32);

    fd = fopen(PROC_PERFCNTR, "w");
    if (fd == NULL)
    {
        perror("open " PROC_PERFCNTR);
        exit(1);
    }
    
    fprintf(fd, "%x %x %llx \n", cpu_mask, msr, value);
    fprintf(stderr, "%x %x %llx \n", cpu_mask, msr, value);
    fclose(fd);
}

static inline unsigned long long perfcntr_rdmsr( int cpu_mask, int msr )
{
    fprintf(stderr, "WARNING: rdmsr not yet implemented for perfcntr.\n");
    return 0;
}

// End of $RCSfile: cpuperf_perfcntr.h,v $

