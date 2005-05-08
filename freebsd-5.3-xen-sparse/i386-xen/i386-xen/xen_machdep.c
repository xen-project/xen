/*
 *
 * Copyright (c) 2004 Christian Limpach.
 * Copyright (c) 2004,2005 Kip Macy
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Christian Limpach.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/reboot.h>


#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/stdarg.h>
#include <machine/xenfunc.h>
#include <machine/xenpmap.h>
#include <machine/vmparam.h>
#include <machine/cpu.h>
#include <machine/xenvar.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/mbuf.h>
#include <nfs/rpcv2.h>
#include <nfsclient/krpc.h>
#include <nfs/nfsproto.h>


shared_info_t *HYPERVISOR_shared_info;

void ni_cli(void);
void ni_sti(void);
#ifdef NFS_ROOT

static int
xdr_opaque_decode(struct mbuf **mptr, u_char *buf, int len)
{
    struct mbuf *m;
    int alignedlen;

    m = *mptr;
    alignedlen = ( len + 3 ) & ~3;

    if (m->m_len < alignedlen) {
	m = m_pullup(m, alignedlen);
	if (m == NULL) {
	    *mptr = NULL;
	    return EBADRPC;
	}
    }
    bcopy(mtod(m, u_char *), buf, len);
    m_adj(m, alignedlen);
    *mptr = m;
    return 0;
}


static int
getdec(char **ptr)
{
    char *p;
    int ret;

    p = *ptr;
    ret = 0;
    if ((*p < '0') || (*p > '9'))
	return -1;
    while ((*p >= '0') && (*p <= '9')) {
	ret = ret * 10 + (*p - '0');
	p++;
    }
    *ptr = p;
    return ret;
}

int
setinaddr(struct sockaddr_in *addr,  char *ipstr)
{
    unsigned int ip;
    int val;

    ip = 0;
    if (((val = getdec(&ipstr)) < 0) || (val > 255))
	return 1;
    ip = val << 24;
    if (*ipstr != '.')
	return 1;
    ipstr++;
    if (((val = getdec(&ipstr)) < 0) || (val > 255))
	return 1;
    ip |= (val << 16);
    if (*ipstr != '.')
	return 1;
    ipstr++;
    if (((val = getdec(&ipstr)) < 0) || (val > 255))
	return 1;
    ip |= (val << 8);
    if (*ipstr != '.')
	return 1;
    ipstr++;
    if (((val = getdec(&ipstr)) < 0) || (val > 255))
	return 1;
    ip |= val;

    addr->sin_addr.s_addr = htonl(ip);
    addr->sin_len = sizeof(struct sockaddr_in);
    addr->sin_family = AF_INET;

    return 0;
}

static int
hwaddr_to_sockaddr(char *ev, struct sockaddr_dl *sa)
{
    char *cp;
    u_int32_t a[6];
    int count;

    bzero(sa, sizeof(*sa));
    sa->sdl_len = sizeof(*sa);
    sa->sdl_family = AF_LINK;
    sa->sdl_type = IFT_ETHER;
    sa->sdl_alen = ETHER_ADDR_LEN;
    if ((cp = getenv(ev)) == NULL)
	return (1);
    count = sscanf(cp, "%x:%x:%x:%x:%x:%x",
		   &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]);
    freeenv(cp);
    if (count != 6)
	return (1);
    sa->sdl_data[0] = a[0];
    sa->sdl_data[1] = a[1];
    sa->sdl_data[2] = a[2];
    sa->sdl_data[3] = a[3];
    sa->sdl_data[4] = a[4];
    sa->sdl_data[5] = a[5];
    return (0);
}
extern int in_control(struct socket *so, u_long cmd,
	   caddr_t data, struct ifnet *ifp,
	   struct thread *td);

static int
xen_setnetwork(void)
{
    int error = 0;
    struct ifaddr *ifa;
    struct ifnet *ifp;
    struct sockaddr_dl *sdl, ourdl;

    if (sizeof(struct sockaddr) != sizeof(struct sockaddr_in))
	panic("sizes not equal\n");

    if (hwaddr_to_sockaddr("boot.netif.hwaddr", &ourdl)) {
	printf("nfs_diskless: no hardware address\n");
	return -1;
    }


    ifa = NULL;
    IFNET_RLOCK();
    TAILQ_FOREACH(ifp, &ifnet, if_link) {
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
	    if ((ifa->ifa_addr->sa_family == AF_LINK) &&
		(sdl = ((struct sockaddr_dl *)ifa->ifa_addr))) {
		if ((sdl->sdl_type == ourdl.sdl_type) &&
		    (sdl->sdl_alen == ourdl.sdl_alen) &&
		    !bcmp(sdl->sdl_data + sdl->sdl_nlen,
			  ourdl.sdl_data + ourdl.sdl_nlen,
			  sdl->sdl_alen)) {
		    IFNET_RUNLOCK();
		    goto match_done;
		}
	    }
	}
    }
    IFNET_RUNLOCK();
    printf("nfs_diskless: no interface\n");
    return -1; /* no matching interface */
 match_done:

    if (getenv("boot.netif.ip") && getenv("boot.netif.gateway") && 
	getenv("boot.netif.netmask")) {
	struct ifaliasreq ifra;
	char *ip;
	
	bzero(&ifra, sizeof(ifra));
	strcpy(ifra.ifra_name, "xn0");
	ip = getenv("boot.netif.ip");
	setinaddr((struct sockaddr_in *)&(ifra.ifra_addr), ip);
	printf("setting ip to %s\n", ip);
	ip = getenv("boot.netif.netmask");
	setinaddr((struct sockaddr_in *)&ifra.ifra_mask, ip);
	setinaddr((struct sockaddr_in *)&ifra.ifra_broadaddr, "255.255.255.255");


	if ((error = in_control(NULL, SIOCAIFADDR,  (caddr_t) &ifra, ifp, curthread))) 
	    printf("couldn't set interface address %d\n", error);
#if 0
	if ((error = xn_ioctl(ifp, SIOCSIFNETMASK, (caddr_t)&ifa)))
	    printf("couldn't set interface netmask %d\n", error);
#endif
    }
    return error;
}

int
xen_setnfshandle(void) 
{
    char *path, *ip;
    u_char fhp[NFSX_V2FH];
    int error = 0;
    struct sockaddr_in sin_local, *sin ;
    struct mbuf *m;

    if ((error = xen_setnetwork())) 
	return error;
    
    sin = &sin_local; 
    
    path = getenv("boot.nfsroot.path");
    ip = getenv("boot.nfsroot.server");

    /* we aren't configured for NFS root */ 
    if (!path || !ip)
	return 0;

    error = setinaddr(sin, ip);
    if (error) {
	printf("invalid ip address %s\n", ip);
	return error;
    }
 
    error = krpc_portmap(sin, RPCPROG_MNT, RPCMNT_VER1,
			 &sin->sin_port, curthread);
    if (error) { 
	printf("failed to find port number for mountd\n");
	return error;
    }
    m = xdr_string_encode(path, strlen(path));
    
    /* Do RPC to mountd */
    error = krpc_call(sin, RPCPROG_MNT, RPCMNT_VER1,
		      RPCMNT_MOUNT, &m, NULL, curthread);
    if (error) {
	printf("call to mountd failed\n");
	return error;
    }
    
    if (xdr_opaque_decode(&m, fhp, NFSX_V2FH) != 0) {
	printf("failed to decode nfs file handle\n");
	return error;
    }

    setenv("boot.nfsroot.nfshandle", fhp);

    return 0;
}
#endif
void
ni_cli(void)
{
    __asm__("pushl %edx;"
	    "pushl %eax;"
	    );
    __cli();
    __asm__("popl %eax;"
	    "popl %edx;"
	    );
}


void
ni_sti(void)
{
    __asm__("pushl %edx;"
	    "pushl %esi;"
	    "pushl %eax;"
	    );
    __sti();
    __asm__("popl %eax;"
	    "popl %esi;"
	    "popl %edx;"
	    );
}

/*
 * Modify the cmd_line by converting ',' to NULLs so that it is in a  format 
 * suitable for the static env vars.
 */
char *
xen_setbootenv(char *cmd_line)
{
     char *cmd_line_next;
    
    for (cmd_line_next = cmd_line; strsep(&cmd_line_next, ",") != NULL;);
    return cmd_line;
}

static struct 
{
    const char	*ev;
    int		mask;
} howto_names[] = {
    {"boot_askname",	RB_ASKNAME},
    {"boot_cdrom",	RB_CDROM},
    {"boot_userconfig",	RB_CONFIG},
    {"boot_ddb",	RB_KDB},
    {"boot_gdb",	RB_GDB},
    {"boot_gdb_pause",	RB_GDB_PAUSE},
    {"boot_single",	RB_SINGLE},
    {"boot_verbose",	RB_VERBOSE},
    {"boot_multicons",	RB_MULTIPLE},
    {"boot_serial",	RB_SERIAL},
    {NULL,	0}
};

int 
xen_boothowto(char *envp)
{
    int i, howto = 0;

    /* get equivalents from the environment */
    for (i = 0; howto_names[i].ev != NULL; i++)
	if (getenv(howto_names[i].ev) != NULL)
	    howto |= howto_names[i].mask;
    return howto;
}

#define PRINTK_BUFSIZE 1024
void
printk(const char *fmt, ...)
{
        __va_list ap;
        int ret;
        static char buf[PRINTK_BUFSIZE];

        va_start(ap, fmt);
        ret = vsnprintf(buf, PRINTK_BUFSIZE - 1, fmt, ap);
        va_end(ap);
        buf[ret] = 0;
        (void)HYPERVISOR_console_write(buf, ret);
}


#define XPQUEUE_SIZE 128
#ifdef SMP
/* per-cpu queues and indices */
static mmu_update_t xpq_queue[MAX_VIRT_CPUS][XPQUEUE_SIZE];
static int xpq_idx[MAX_VIRT_CPUS];  

#define XPQ_QUEUE xpq_queue[vcpu]
#define XPQ_IDX xpq_idx[vcpu]
#define SET_VCPU() int vcpu = smp_processor_id()
#else
static mmu_update_t xpq_queue[XPQUEUE_SIZE];
static int xpq_idx = 0;

#define XPQ_QUEUE xpq_queue
#define XPQ_IDX xpq_idx
#define SET_VCPU()
#endif
#define XPQ_IDX_INC atomic_add_int(&XPQ_IDX, 1);


static __inline void
_xen_flush_queue(void)
{
    SET_VCPU();
    int _xpq_idx = XPQ_IDX;
    int error, i;
    /* window of vulnerability here? */

    XPQ_IDX = 0;
    /* Make sure index is cleared first to avoid double updates. */
    error = HYPERVISOR_mmu_update((mmu_update_t *)&XPQ_QUEUE,
				  _xpq_idx, NULL, DOMID_SELF);
    
    if (__predict_false(error < 0)) {
	for (i = 0; i < _xpq_idx; i++)
	    printk("val: %x ptr: %p\n", XPQ_QUEUE[i].val, XPQ_QUEUE[i].ptr);
	panic("Failed to execute MMU updates: %d", error);
    }

}

void
xen_flush_queue(void)
{
    SET_VCPU();
    if (XPQ_IDX != 0) _xen_flush_queue();
}

static __inline void
xen_increment_idx(void)
{
    SET_VCPU();

    XPQ_IDX++;
    if (__predict_false(XPQ_IDX == XPQUEUE_SIZE))
	xen_flush_queue();
}

void
xen_invlpg(vm_offset_t va)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_INVLPG_LOCAL;
    op.linear_addr = va & ~PAGE_MASK;
    xen_flush_queue();
    PANIC_IF(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void
load_cr3(uint32_t val)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_NEW_BASEPTR;
    op.mfn = xpmap_ptom(val) >> PAGE_SHIFT;
    xen_flush_queue();
    PANIC_IF(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}


void
xen_machphys_update(unsigned long mfn, unsigned long pfn)
{
    SET_VCPU();
    
    XPQ_QUEUE[XPQ_IDX].ptr = (mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
    XPQ_QUEUE[XPQ_IDX].val = pfn;
    xen_increment_idx();
    _xen_flush_queue();
}

void
xen_queue_pt_update(vm_paddr_t ptr, vm_paddr_t val)
{
    SET_VCPU();
    
    XPQ_QUEUE[XPQ_IDX].ptr = (memory_t)ptr;
    XPQ_QUEUE[XPQ_IDX].val = (memory_t)val;
    xen_increment_idx();
}

void 
xen_pgd_pin(unsigned long ma)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_PIN_L2_TABLE;
    op.mfn = ma >> PAGE_SHIFT;
    xen_flush_queue();
    PANIC_IF(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void 
xen_pgd_unpin(unsigned long ma)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_UNPIN_TABLE;
    op.mfn = ma >> PAGE_SHIFT;
    xen_flush_queue();
    PANIC_IF(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void 
xen_pt_pin(unsigned long ma)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_PIN_L1_TABLE;
    op.mfn = ma >> PAGE_SHIFT;
    xen_flush_queue();
    PANIC_IF(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void 
xen_pt_unpin(unsigned long ma)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_UNPIN_TABLE;
    op.mfn = ma >> PAGE_SHIFT;
    xen_flush_queue();
    PANIC_IF(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void 
xen_set_ldt(unsigned long ptr, unsigned long len)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_SET_LDT;
    op.linear_addr = ptr;
    op.nr_ents = len;
    xen_flush_queue();
    PANIC_IF(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_tlb_flush(void)
{
    struct mmuext_op op;
    op.cmd = MMUEXT_TLB_FLUSH_LOCAL;
    xen_flush_queue();
    PANIC_IF(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}


/********** CODE WORTH KEEPING ABOVE HERE *****************/ 

void xen_failsafe_handler(void);

void
xen_failsafe_handler(void)
{

	panic("xen_failsafe_handler called!\n");
}


void
xen_update_descriptor(union descriptor *table, union descriptor *entry)
{
	vm_paddr_t pa;
	pt_entry_t *ptp;
	uint32_t raw[2];

	bcopy(entry, raw, 2*sizeof(int32_t));
	ptp = vtopte((vm_offset_t)table);
	pa = (*ptp & PG_FRAME) | ((vm_offset_t)table & PAGE_MASK);
	if (HYPERVISOR_update_descriptor(pa, raw[0], raw[1]))
		panic("HYPERVISOR_update_descriptor failed\n");
}



#if defined(XENDEBUG)
static void
xpmap_dump_pt(pt_entry_t *ptp, int p)
{
	pt_entry_t pte;
	int j;
	int bufpos;

	pte = xpmap_ptom((uint32_t)ptp - KERNTEXTOFF);
	PRINTK(("%03x: %p(%p) %08x\n", p, ptp, (void *)pte, p << PDRSHIFT));

	bufpos = 0;
	for (j = 0; j < PTES_PER_PTP; j++) {
		if ((ptp[j] & PG_V) == 0)
			continue;
		pte = ptp[j] /* & PG_FRAME */;
		bufpos += sprintf(XBUF + bufpos, "%x:%03x:%08x ",
		    p, j, pte);
		if (bufpos > 70) {
			int k;
			sprintf(XBUF + bufpos, "\n");
			PRINTK((XBUF));
			bufpos = 0;
			for (k = 0; k < 1000000; k++);
		}
	}
	if (bufpos) {
		PRINTK((XBUF));
		bufpos = 0;
	}
}
#endif


