/*	$NetBSD:$	*/

/*
 *
 * Copyright (c) 2004 Christian Limpach.
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


#ifndef _XEN_XENFUNC_H_
#define _XEN_XENFUNC_H_

#include <machine/xen-os.h>
#include <machine/hypervisor.h>
#include <machine/xenpmap.h>
#include <machine/segments.h>
#include <sys/pcpu.h>
#define BKPT __asm__("int3");
#define XPQ_CALL_DEPTH 5
#define XPQ_CALL_COUNT 2
#define PG_PRIV PG_AVAIL3
typedef struct { 
	unsigned long pt_ref;
	unsigned long pt_eip[XPQ_CALL_COUNT][XPQ_CALL_DEPTH];
} pteinfo_t;

extern pteinfo_t *pteinfo_list;
#ifdef XENDEBUG_LOW
#define	__PRINTK(x) printk x
#else
#define	__PRINTK(x)
#endif

char *xen_setbootenv(char *cmd_line);
int xen_boothowto(char *envp);
void load_cr3(uint32_t val);
void xen_set_ldt(vm_offset_t, uint32_t);
void xen_machphys_update(unsigned long, unsigned long);
void xen_update_descriptor(union descriptor *, union descriptor *);
void lldt(u_short sel);
/*
 * Invalidate a patricular VA on all cpus
 *
 * N.B. Made these global for external loadable modules to reference.
 */
static __inline void
invlpg(u_int addr)
{
	xpq_queue_invlpg(addr);
}

static __inline void
invltlb(void)
{
	xpq_queue_tlb_flush();
	mcl_flush_queue();
}


#endif /* _XEN_XENFUNC_H_ */
