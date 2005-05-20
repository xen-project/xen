/*
 *  i386 helpers (without register variable usage)
 * 
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

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
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <assert.h>

#include <limits.h>
#include <fcntl.h>

#include "xc.h"
#include <io/ioreq.h>

#include "cpu.h"
#include "exec-all.h"

void *shared_page;

CPUX86State *cpu_86_init(void)
{
    CPUX86State *env;
    static int inited;

    cpu_exec_init();

    env = malloc(sizeof(CPUX86State));
    if (!env)
        return NULL;
    memset(env, 0, sizeof(CPUX86State));
    /* init various static tables */
    if (!inited) {
        inited = 1;
    }
    cpu_single_env = env;
    cpu_reset(env);
    return env;
}

/* NOTE: must be called outside the CPU execute loop */
void cpu_reset(CPUX86State *env)
{
}

void cpu_x86_close(CPUX86State *env)
{
    free(env);
}


void cpu_dump_state(CPUState *env, FILE *f, 
                    int (*cpu_fprintf)(FILE *f, const char *fmt, ...),
                    int flags)
{
}

/***********************************************************/
/* x86 mmu */
/* XXX: add PGE support */

void cpu_x86_set_a20(CPUX86State *env, int a20_state)
{
    a20_state = (a20_state != 0);
    if (a20_state != ((env->a20_mask >> 20) & 1)) {
#if defined(DEBUG_MMU)
        printf("A20 update: a20=%d\n", a20_state);
#endif
        env->a20_mask = 0xffefffff | (a20_state << 20);
    }
}

target_ulong cpu_get_phys_page_debug(CPUState *env, target_ulong addr)
{
        return addr;
}

//the evtchn fd for polling
int evtchn_fd = -1;
//the evtchn port for polling the notification, should be inputed as bochs's parameter
u16 ioreq_port = 0;

void *shared_page = NULL;

//some functions to handle the io req packet

//get the ioreq packets from share mem
ioreq_t* __cpu_get_ioreq(void)
{
	ioreq_t *req;
	req = &((vcpu_iodata_t *) shared_page)->vp_ioreq;
	if (req->state == STATE_IOREQ_READY) {
		req->state = STATE_IOREQ_INPROCESS;
	} else {
		fprintf(logfile, "False I/O requrest ... in-service already: %x, pvalid: %x,port: %llx, data: %llx, count: %llx, size: %llx\n", req->state, req->pdata_valid, req->addr, req->u.data, req->count, req->size);
		req = NULL;
	}

	return req;
}

//use poll to get the port notification
//ioreq_vec--out,the 
//retval--the number of ioreq packet
ioreq_t* cpu_get_ioreq(void)
{
	int rc;
	u16 buf[2];
	rc = read(evtchn_fd, buf, 2);
	if (rc == 2 && buf[0] == ioreq_port){//got only one matched 16bit port index
		// unmask the wanted port again
		write(evtchn_fd, &ioreq_port, 2);

		//get the io packet from shared memory
		return __cpu_get_ioreq();
	}

	//read error or read nothing
	return NULL;
}

unsigned long
do_inp(CPUState *env, unsigned long addr, unsigned long size)
{
  switch(size) {
      case 1:
        return cpu_inb(env, addr);
      case 2:
        return cpu_inw(env, addr);
      case 4:
        return cpu_inl(env, addr);
      default:
	fprintf(logfile, "inp: bad size: %lx %lx\n", addr, size);
        exit(-1);
  }
}

void
do_outp(CPUState *env, unsigned long addr, unsigned long size, 
        unsigned long val)
{
  switch(size) {
      case 1:
        return cpu_outb(env, addr, val);
      case 2:
        return cpu_outw(env, addr, val);
      case 4:
        return cpu_outl(env, addr, val);
      default:
	fprintf(logfile, "outp: bad size: %lx %lx\n", addr, size);
        exit(-1);
  }
}

extern void cpu_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, 
                                   int len, int is_write);

static inline void
read_physical(target_phys_addr_t addr, unsigned long size, void *val)
{
        return cpu_physical_memory_rw(addr, val, size, 0);
}

static inline void
write_physical(target_phys_addr_t addr, unsigned long size, void *val)
{
        return cpu_physical_memory_rw(addr, val, size, 1);
}

//send the ioreq to device model
void cpu_dispatch_ioreq(CPUState *env, ioreq_t *req)
{
	int i;
	int sign;

	sign = (req->df) ? -1 : 1;

	if ((!req->pdata_valid) && (req->dir == IOREQ_WRITE)) {
		if (req->size != 4) {
			// Bochs expects higher bits to be 0
			req->u.data &= (1UL << (8 * req->size))-1;
		}
	}

	if (req->port_mm == 0){//port io
		if(req->dir == IOREQ_READ){//read
			if (!req->pdata_valid) {
				req->u.data = do_inp(env, req->addr, req->size);
			} else {
				unsigned long tmp; 

				for (i = 0; i < req->count; i++) {
					tmp = do_inp(env, req->addr, req->size);
					write_physical((target_phys_addr_t)req->u.pdata + (sign * i * req->size), 
						       req->size, &tmp);
				}
			}
		} else if(req->dir == IOREQ_WRITE) {
			if (!req->pdata_valid) {
				do_outp(env, req->addr, req->size, req->u.data);
			} else {
				for (i = 0; i < req->count; i++) {
					unsigned long tmp;

					read_physical((target_phys_addr_t)req->u.pdata + (sign * i * req->size), req->size, 
						      &tmp);
					do_outp(env, req->addr, req->size, tmp);
				}
			}
			
		}
	} else if (req->port_mm == 1){//memory map io
		if (!req->pdata_valid) {
			//handle stos
			if(req->dir == IOREQ_READ) { //read
				for (i = 0; i < req->count; i++) {
					read_physical((target_phys_addr_t)req->addr + (sign * i * req->size), req->size, &req->u.data);
				}
			} else if(req->dir == IOREQ_WRITE) { //write
				for (i = 0; i < req->count; i++) {
					write_physical((target_phys_addr_t)req->addr + (sign * i * req->size), req->size, &req->u.data);
				}
			}
		} else {
			//handle movs
			unsigned long tmp;
			if (req->dir == IOREQ_READ) {
				for (i = 0; i < req->count; i++) {
					read_physical((target_phys_addr_t)req->addr + (sign * i * req->size), req->size, &tmp);
					write_physical((target_phys_addr_t)req->u.pdata + (sign * i * req->size), req->size, &tmp);
				}
			} else if (req->dir == IOREQ_WRITE) {
				for (i = 0; i < req->count; i++) {
					read_physical((target_phys_addr_t)req->u.pdata + (sign * i * req->size), req->size, &tmp);
					write_physical((target_phys_addr_t)req->addr + (sign * i * req->size), req->size, &tmp);
				}
			}
		}
	}
        /* No state change if state = STATE_IORESP_HOOK */
        if (req->state == STATE_IOREQ_INPROCESS)
                req->state = STATE_IORESP_READY;
	env->send_event = 1;
}

void
cpu_handle_ioreq(CPUState *env)
{
	ioreq_t *req = cpu_get_ioreq();
	if (req)
		cpu_dispatch_ioreq(env, req);
}

void
cpu_timer_handler(CPUState *env)
{
	cpu_handle_ioreq(env);
}

int xc_handle;

static __inline__ void atomic_set_bit(long nr, volatile void *addr)
{
        __asm__ __volatile__(
                "lock ; bts %1,%0"
                :"=m" (*(volatile long *)addr)
                :"dIr" (nr));
}

void
do_interrupt(CPUState *env, int vector)
{
	unsigned long *intr;

	// Send a message on the event channel. Add the vector to the shared mem
	// page.

	intr = &(((vcpu_iodata_t *) shared_page)->vp_intr[0]);
	atomic_set_bit(vector, intr);
        fprintf(logfile, "injecting vector: %x\n", vector);
	env->send_event = 1;
}

//static unsigned long tsc_per_tick = 1; /* XXX: calibrate */

int main_loop(void)
{
	int vector;
 	fd_set rfds;
	struct timeval tv;
	extern CPUState *global_env;
        extern int vm_running;
        extern int shutdown_requested;
	CPUState *env = global_env;
	int retval;
        extern void main_loop_wait(int);

 	/* Watch stdin (fd 0) to see when it has input. */
	FD_ZERO(&rfds);

	while (1) {
            if (vm_running) {
                if (shutdown_requested) {
                    break;
                }
            }

		/* Wait up to one seconds. */
		tv.tv_sec = 0;
		tv.tv_usec = 100000;
		FD_SET(evtchn_fd, &rfds);

		env->send_event = 0;
		retval = select(evtchn_fd+1, &rfds, NULL, NULL, &tv);
		if (retval == -1) {
			perror("select");
			return 0;
		}

#if __WORDSIZE == 32
#define ULONGLONG_MAX   0xffffffffffffffffULL
#else
#define ULONGLONG_MAX   ULONG_MAX
#endif

		main_loop_wait(0);

		cpu_timer_handler(env);
		if (env->interrupt_request & CPU_INTERRUPT_HARD) {
                        env->interrupt_request &= ~CPU_INTERRUPT_HARD;
			vector = cpu_get_pic_interrupt(env); 
			do_interrupt(env, vector);
		}

		if (env->send_event) {
			int ret;
			ret = xc_evtchn_send(xc_handle, ioreq_port);
			if (ret == -1) {
				fprintf(logfile, "evtchn_send failed on port: %d\n", ioreq_port);
			}
		}
	}
	return 0;
}

CPUState *
cpu_init()
{
	CPUX86State *env;
      
        cpu_exec_init();

	env = malloc(sizeof(CPUX86State));
	if (!env)
		return NULL;
	memset(env, 0, sizeof(CPUX86State));

	cpu_single_env = env;

	if (evtchn_fd != -1)//the evtchn has been opened by another cpu object
		return NULL;

	//use nonblock reading not polling, may change in future.
	evtchn_fd = open("/dev/xen/evtchn", O_RDWR|O_NONBLOCK); 
	if (evtchn_fd == -1) {
		perror("open");
		return NULL;
	}

	fprintf(logfile, "listening to port: %d\n", ioreq_port);
	/*unmask the wanted port -- bind*/
	if (ioctl(evtchn_fd, ('E'<<8)|2, ioreq_port) == -1) {
		perror("ioctl");
		return NULL;
	}

	return env;
}
