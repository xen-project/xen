/*
 * Main cpu loop for handling I/O requests coming from a virtual machine
 * Copyright © 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "bochs.h"
#include <cpu/cpu.h>
#ifdef BX_USE_VMX
#include <sys/ioctl.h>
/* According to POSIX 1003.1-2001 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <values.h>
#endif

#define LOG_THIS BX_CPU_THIS_PTR

#ifdef BX_USE_VMX

//the evtchn fd for polling
int evtchn_fd = -1;
//the evtchn port for polling the notification, should be inputed as bochs's parameter
u16 ioreq_port = 0;

void *shared_page = NULL;

//some functions to handle the io req packet

//get the ioreq packets from share mem
ioreq_t* bx_cpu_c::__get_ioreq(void)
{
	ioreq_t *req;
	req = &((vcpu_iodata_t *) shared_page)->vp_ioreq;
	if (req->state == STATE_IOREQ_READY) {
		req->state = STATE_IOREQ_INPROCESS;
	} else {
		BX_INFO(("False I/O requrest ... in-service already: %lx, pvalid: %lx,port: %lx, data: %lx, count: %lx, size: %lx\n", req->state, req->pdata_valid, req->addr, req->u.data, req->count, req->size));
		req = NULL;
	}

	return req;
}

//use poll to get the port notification
//ioreq_vec--out,the 
//retval--the number of ioreq packet
ioreq_t* bx_cpu_c::get_ioreq(void)
{
	ioreq_t *req;
	int rc;
	u16 buf[2];
	rc = read(evtchn_fd, buf, 2);
	if (rc == 2 && buf[0] == ioreq_port){//got only one matched 16bit port index
		// unmask the wanted port again
		write(evtchn_fd, &ioreq_port, 2);

		//get the io packet from shared memory
		return __get_ioreq();
	}

	//read error or read nothing
	return NULL;
}

//send the ioreq to device model
void bx_cpu_c::dispatch_ioreq(ioreq_t *req)
{
	int ret, i;

	if ((!req->pdata_valid) && (req->dir == IOREQ_WRITE)) {
		if (req->size != 4) {
			// Bochs expects higher bits to be 0
			req->u.data &= (1UL << (8 * req->size))-1;
		}
	}
	if (req->port_mm == 0){//port io
		if(req->dir == IOREQ_READ){//read
			if (!req->pdata_valid)
				req->u.data = BX_INP(req->addr, req->size);
			else {
				unsigned long tmp; 

				for (i = 0; i < req->count; i++) {
					tmp = BX_INP(req->addr, req->size);
					BX_MEM_WRITE_PHYSICAL((Bit32u) req->u.pdata + (i * req->size), 
							       req->size, &tmp);
				}
			}
		} else if(req->dir == IOREQ_WRITE) {
			if (!req->pdata_valid) {
				BX_OUTP(req->addr, (Bit32u) req->u.data, req->size);
			} else {
				for (i = 0; i < req->count; i++) {
					unsigned long tmp;

					BX_MEM_READ_PHYSICAL((Bit32u) req->u.pdata + (i * req->size), req->size, 
							 &tmp);
					BX_OUTP(req->addr, (Bit32u) tmp, req->size);
				}
			}
			
		}
	} else if (req->port_mm == 1){//memory map io
		if (!req->pdata_valid) {
			if(req->dir == IOREQ_READ){//read
				BX_MEM_READ_PHYSICAL(req->addr, req->size, &req->u.data);
			} else if(req->dir == IOREQ_WRITE)//write
				BX_MEM_WRITE_PHYSICAL(req->addr, req->size, &req->u.data);
		} else {
			//handle movs
			unsigned long tmp;
			if (req->dir == IOREQ_READ) {
				//BX_INFO(("<READ>addr:%llx, pdata:%llx, size: %x, count: %x\n", req->addr, req->u.pdata, req->size, req->count));
				for (i = 0; i < req->count; i++) {
					BX_MEM_READ_PHYSICAL(req->addr + (i * req->size), req->size, &tmp);
					BX_MEM_WRITE_PHYSICAL((Bit32u) req->u.pdata + (i * req->size), req->size, &tmp);
				}
			} else if (req->dir == IOREQ_WRITE) {
				//BX_INFO(("<WRITE>addr:%llx, pdata:%llx, size: %x, count: %x\n", req->addr, req->u.pdata, req->size, req->count));
				for (i = 0; i < req->count; i++) {
					BX_MEM_READ_PHYSICAL((Bit32u)req->u.pdata + (i * req->size), req->size, &tmp);
					BX_MEM_WRITE_PHYSICAL(req->addr + (i * req->size), req->size, &tmp);
				}
			}
		}
	}
	req->state = STATE_IORESP_READY;
	send_event = 1;
}

void
bx_cpu_c::handle_ioreq(void)
{
	ioreq_t *req = get_ioreq();
	if (req)
		dispatch_ioreq(req);
}

void
bx_cpu_c::timer_handler(void)
{
	handle_ioreq();
}

#endif

#define rdtscl(low) \
     __asm__ __volatile__("rdtsc" : "=a" (low) : : "edx")

void
bx_cpu_c::cpu_loop(int max_instr_count)
{
	Bit8u vector;
 	fd_set rfds;
	unsigned long stime_usec;
	struct timeval tv;
	int retval;

 	/* Watch stdin (fd 0) to see when it has input. */
	FD_ZERO(&rfds);

	while (1) {
		unsigned long t1, t2;

		/* Wait up to one seconds. */
		tv.tv_sec = 0;
		tv.tv_usec = 100000;
		FD_SET(evtchn_fd, &rfds);

		send_event = 0;
		rdtscl(t1);		
		retval = select(evtchn_fd+1, &rfds, NULL, NULL, &tv);
		rdtscl(t2);
		if (retval == -1) {
			perror("select");
			return;
		}
		//stime_usec = 1000000 * (1 - tv.tv_sec)  - tv.tv_usec;
		if (t2 > t1)
			BX_TICKN((t2 - t1) / 2000);	// should match ips in bochsrc
		else
			BX_TICKN((MAXINT - t1 + t2) / 2000);	// should match ips in bochsrc
		timer_handler();
		if (BX_CPU_INTR) {
#if BX_SUPPORT_APIC
			if (BX_CPU_THIS_PTR local_apic.INTR)
				vector = BX_CPU_THIS_PTR local_apic.acknowledge_int ();
			else
				vector = DEV_pic_iac(); // may set INTR with next interrupt
#else
			// if no local APIC, always acknowledge the PIC.
			vector = DEV_pic_iac(); // may set INTR with next interrupt
#endif
			interrupt(vector);
		}

		if (send_event) {
			int ret;
			ret = xc_evtchn_send(xc_handle, ioreq_port);
			if (ret == -1) {
				BX_ERROR(("evtchn_send failed on port: %d\n", ioreq_port));
			}
		}
	}
}

static __inline__ void set_bit(long nr, volatile void *addr)
{
	__asm__ __volatile__( "lock ; "
		"btsl %1,%0"
		:"=m" ((*(volatile long *)addr))
		:"Ir" (nr));

	return;
}

void
bx_cpu_c::interrupt(Bit8u vector)
{
	unsigned long *intr, tscl;
	int ret;

	// Send a message on the event channel. Add the vector to the shared mem
	// page.

	rdtscl(tscl);
	BX_INFO(("%lx: injecting vector: %x\n", tscl, vector));
	intr = &(((vcpu_iodata_t *) shared_page)->vp_intr[0]);
	set_bit(vector, intr);
	
	send_event = 1;
}

void
bx_cpu_c::init(bx_mem_c*)
{
#ifdef BX_USE_VMX
	if (evtchn_fd != -1)//the evtchn has been opened by another cpu object
		return;

	//use nonblock reading not polling, may change in future.
	evtchn_fd = open("/dev/xen/evtchn", O_RDWR|O_NONBLOCK); 
	if (evtchn_fd == -1) {
		perror("open");
		return;
	}

	BX_INFO(("listening to port: %d\n", ioreq_port));
	/*unmask the wanted port -- bind*/
	if (ioctl(evtchn_fd, ('E'<<8)|2, ioreq_port) == -1) {
		perror("ioctl");
		return;
	}

#if 0	
	//register the reading evtchn function as timer
	bx_pc_system.register_timer(this, timer_handler, 1000,//1000 us, may change
			1,//continuous timer
			1,//active
			"cpu reading evtchn handler");
#endif

#endif
}

void
bx_cpu_c::reset(unsigned)
{
}

void
bx_cpu_c::atexit()
{
}

void
bx_cpu_c::set_INTR(unsigned value)
{
	BX_CPU_THIS_PTR INTR = value;
}

void
bx_cpu_c::pagingA20Changed()
{
}

bx_cpu_c::bx_cpu_c()
{
}

bx_cpu_c::~bx_cpu_c()
{
}
