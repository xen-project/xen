#ifndef XENVAR_H_
#define XENVAR_H_

#define XBOOTUP 0x1
#define XPMAP   0x2
extern int xendebug_flags;
#ifndef NOXENDEBUG
#define XENPRINTF printk
#else
#define XENPRINTF(x...)
#endif 
extern unsigned long *xen_phys_machine;
#define TRACE_ENTER XENPRINTF("(file=%s, line=%d) entered %s\n", __FILE__, __LINE__, __FUNCTION__)
#define TRACE_EXIT XENPRINTF("(file=%s, line=%d) exiting %s\n", __FILE__, __LINE__, __FUNCTION__)
#define TRACE_DEBUG(argflags, _f, _a...) \
if (xendebug_flags & argflags) XENPRINTF("(file=%s, line=%d) " _f "\n", __FILE__, __LINE__, ## _a);

extern unsigned long *xen_machine_phys;
#define PTOM(i) (((unsigned long *)xen_phys_machine)[i])
#define phystomach(pa) ((((unsigned long *)xen_phys_machine)[(pa >> PAGE_SHIFT)]) << PAGE_SHIFT)
void xpq_init(void);

struct sockaddr_in;
 
int xen_setnfshandle(void);
int setinaddr(struct sockaddr_in *addr,  char *ipstr);

#define RB_GDB_PAUSE RB_RESERVED1 

#endif
