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
 *
 * Copyright © 2004, Intel Corporation.
 * Copyright © 2005, International Business Machines Corporation.
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
#include <sys/ioctl.h>

#include <xenctrl.h>
#include <xen/hvm/ioreq.h>
#include <xen/linux/evtchn.h>

#include "cpu.h"
#include "exec-all.h"
#include "vl.h"

extern int domid;
extern int vcpus;

void *shared_vram;

shared_iopage_t *shared_page = NULL;
extern int reset_requested;

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

//which vcpu we are serving
int send_vcpu = 0;

//some functions to handle the io req packet
void sp_info()
{
    ioreq_t *req;
    int i;

    for ( i = 0; i < vcpus; i++ ) {
        req = &(shared_page->vcpu_iodata[i].vp_ioreq);
        term_printf("vcpu %d: event port %d\n",
                    i, shared_page->vcpu_iodata[i].vp_eport);
        term_printf("  req state: %x, pvalid: %x, addr: %llx, "
                    "data: %llx, count: %llx, size: %llx\n",
                    req->state, req->pdata_valid, req->addr,
                    req->u.data, req->count, req->size);
        term_printf("  IO totally occurred on this vcpu: %llx\n",
                    req->io_count);
    }
}

//get the ioreq packets from share mem
static ioreq_t* __cpu_get_ioreq(int vcpu)
{
    ioreq_t *req;

    req = &(shared_page->vcpu_iodata[vcpu].vp_ioreq);

    if ( req->state == STATE_IOREQ_READY )
        return req;

    fprintf(logfile, "False I/O request ... in-service already: "
                     "%x, pvalid: %x, port: %llx, "
                     "data: %llx, count: %llx, size: %llx\n",
                     req->state, req->pdata_valid, req->addr,
                     req->u.data, req->count, req->size);
    return NULL;
}

//use poll to get the port notification
//ioreq_vec--out,the
//retval--the number of ioreq packet
static ioreq_t* cpu_get_ioreq(void)
{
    int i, rc;
    evtchn_port_t port;

    rc = read(evtchn_fd, &port, sizeof(port));
    if ( rc == sizeof(port) ) {
        for ( i = 0; i < vcpus; i++ )
            if ( shared_page->vcpu_iodata[i].dm_eport == port )
                break;

        if ( i == vcpus ) {
            fprintf(logfile, "Fatal error while trying to get io event!\n");
            exit(1);
        }

        // unmask the wanted port again
        write(evtchn_fd, &port, sizeof(port));

        //get the io packet from shared memory
        send_vcpu = i;
        return __cpu_get_ioreq(i);
    }

    //read error or read nothing
    return NULL;
}

unsigned long do_inp(CPUState *env, unsigned long addr, unsigned long size)
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

void do_outp(CPUState *env, unsigned long addr,
             unsigned long size, unsigned long val)
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

static inline void read_physical(uint64_t addr, unsigned long size, void *val)
{
    return cpu_physical_memory_rw((target_phys_addr_t)addr, val, size, 0);
}

static inline void write_physical(uint64_t addr, unsigned long size, void *val)
{
    return cpu_physical_memory_rw((target_phys_addr_t)addr, val, size, 1);
}

void cpu_ioreq_pio(CPUState *env, ioreq_t *req)
{
    int i, sign;

    sign = req->df ? -1 : 1;

    if (req->dir == IOREQ_READ) {
        if (!req->pdata_valid) {
            req->u.data = do_inp(env, req->addr, req->size);
        } else {
            unsigned long tmp;

            for (i = 0; i < req->count; i++) {
                tmp = do_inp(env, req->addr, req->size);
                write_physical((target_phys_addr_t) req->u.pdata
                  + (sign * i * req->size),
                  req->size, &tmp);
            }
        }
    } else if (req->dir == IOREQ_WRITE) {
        if (!req->pdata_valid) {
            do_outp(env, req->addr, req->size, req->u.data);
        } else {
            for (i = 0; i < req->count; i++) {
                unsigned long tmp;

                read_physical((target_phys_addr_t) req->u.pdata
                  + (sign * i * req->size),
                  req->size, &tmp);
                do_outp(env, req->addr, req->size, tmp);
            }
        }
    }
}

void cpu_ioreq_move(CPUState *env, ioreq_t *req)
{
    int i, sign;

    sign = req->df ? -1 : 1;

    if (!req->pdata_valid) {
        if (req->dir == IOREQ_READ) {
            for (i = 0; i < req->count; i++) {
                read_physical(req->addr
                  + (sign * i * req->size),
                  req->size, &req->u.data);
            }
        } else if (req->dir == IOREQ_WRITE) {
            for (i = 0; i < req->count; i++) {
                write_physical(req->addr
                  + (sign * i * req->size),
                  req->size, &req->u.data);
            }
        }
    } else {
        unsigned long tmp;

        if (req->dir == IOREQ_READ) {
            for (i = 0; i < req->count; i++) {
                read_physical(req->addr
                  + (sign * i * req->size),
                  req->size, &tmp);
                write_physical((target_phys_addr_t )req->u.pdata
                  + (sign * i * req->size),
                  req->size, &tmp);
            }
        } else if (req->dir == IOREQ_WRITE) {
            for (i = 0; i < req->count; i++) {
                read_physical((target_phys_addr_t) req->u.pdata
                  + (sign * i * req->size),
                  req->size, &tmp);
                write_physical(req->addr
                  + (sign * i * req->size),
                  req->size, &tmp);
            }
        }
    }
}

void cpu_ioreq_and(CPUState *env, ioreq_t *req)
{
    unsigned long tmp1, tmp2;

    if (req->pdata_valid != 0)
        hw_error("expected scalar value");

    read_physical(req->addr, req->size, &tmp1);
    if (req->dir == IOREQ_WRITE) {
        tmp2 = tmp1 & (unsigned long) req->u.data;
        write_physical(req->addr, req->size, &tmp2);
    }
    req->u.data = tmp1;
}

void cpu_ioreq_or(CPUState *env, ioreq_t *req)
{
    unsigned long tmp1, tmp2;

    if (req->pdata_valid != 0)
        hw_error("expected scalar value");

    read_physical(req->addr, req->size, &tmp1);
    if (req->dir == IOREQ_WRITE) {
        tmp2 = tmp1 | (unsigned long) req->u.data;
        write_physical(req->addr, req->size, &tmp2);
    }
    req->u.data = tmp1;
}

void cpu_ioreq_xor(CPUState *env, ioreq_t *req)
{
    unsigned long tmp1, tmp2;

    if (req->pdata_valid != 0)
        hw_error("expected scalar value");

    read_physical(req->addr, req->size, &tmp1);
    if (req->dir == IOREQ_WRITE) {
        tmp2 = tmp1 ^ (unsigned long) req->u.data;
        write_physical(req->addr, req->size, &tmp2);
    }
    req->u.data = tmp1;
}

void cpu_handle_ioreq(CPUState *env)
{
    ioreq_t *req = cpu_get_ioreq();

    if (req) {
        req->state = STATE_IOREQ_INPROCESS;

        if ((!req->pdata_valid) && (req->dir == IOREQ_WRITE)) {
            if (req->size != 4)
                req->u.data &= (1UL << (8 * req->size))-1;
        }

        switch (req->type) {
        case IOREQ_TYPE_PIO:
            cpu_ioreq_pio(env, req);
            break;
        case IOREQ_TYPE_COPY:
            cpu_ioreq_move(env, req);
            break;
        case IOREQ_TYPE_AND:
            cpu_ioreq_and(env, req);
            break;
        case IOREQ_TYPE_OR:
            cpu_ioreq_or(env, req);
            break;
        case IOREQ_TYPE_XOR:
            cpu_ioreq_xor(env, req);
            break;
        default:
            hw_error("Invalid ioreq type 0x%x\n", req->type);
        }

        /* No state change if state = STATE_IORESP_HOOK */
        if (req->state == STATE_IOREQ_INPROCESS)
            req->state = STATE_IORESP_READY;
        env->send_event = 1;
    }
}

int xc_handle;

void
destroy_hvm_domain(void)
{
    extern FILE* logfile;
    char destroy_cmd[32];

    sprintf(destroy_cmd, "xm destroy %d", domid);
    if (system(destroy_cmd) == -1)
        fprintf(logfile, "%s failed.!\n", destroy_cmd);
}

fd_set wakeup_rfds;
int    highest_fds;
int main_loop(void)
{
    fd_set rfds;
    struct timeval tv;
    extern CPUState *global_env;
    extern int vm_running;
    extern int shutdown_requested;
    CPUState *env = global_env;
    int retval;
    extern void main_loop_wait(int);

    /* Watch stdin (fd 0) to see when it has input. */
    FD_ZERO(&wakeup_rfds);
    FD_SET(evtchn_fd, &wakeup_rfds);
    highest_fds = evtchn_fd;
    env->send_event = 0;

    while (1) {
        if (vm_running) {
            if (shutdown_requested) {
                break;
            }
            if (reset_requested){
                qemu_system_reset();
                reset_requested = 0;
            }
        }

        /* Wait up to one seconds. */
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        retval = select(highest_fds+1, &wakeup_rfds, NULL, NULL, &tv);
        if (retval == -1) {
            fprintf(logfile, "select returned error %d\n", errno);
            return 0;
        }
        rfds = wakeup_rfds;
        FD_ZERO(&wakeup_rfds);
        FD_SET(evtchn_fd, &wakeup_rfds);

#if __WORDSIZE == 32
#define ULONGLONG_MAX   0xffffffffffffffffULL
#else
#define ULONGLONG_MAX   ULONG_MAX
#endif

        tun_receive_handler(&rfds);
        if ( FD_ISSET(evtchn_fd, &rfds) ) {
            cpu_handle_ioreq(env);
        }
        main_loop_wait(0);

        if (env->send_event) {
            struct ioctl_evtchn_notify notify;

            env->send_event = 0;
            notify.port = shared_page->vcpu_iodata[send_vcpu].dm_eport;
            (void)ioctl(evtchn_fd, IOCTL_EVTCHN_NOTIFY, &notify);
        }
    }
    destroy_hvm_domain();
    return 0;
}

static void qemu_hvm_reset(void *unused)
{
    char cmd[64];

    /* pause domain first, to avoid repeated reboot request*/
    xc_domain_pause(xc_handle, domid);

    sprintf(cmd, "xm shutdown -R %d", domid);
    system(cmd);
}

CPUState * cpu_init()
{
    CPUX86State *env;
    struct ioctl_evtchn_bind_interdomain bind;
    int i, rc;

    cpu_exec_init();
    qemu_register_reset(qemu_hvm_reset, NULL);
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
        fprintf(logfile, "open evtchn device error %d\n", errno);
        return NULL;
    }

    /* FIXME: how about if we overflow the page here? */
    bind.remote_domain = domid;
    for ( i = 0; i < vcpus; i++ ) {
        bind.remote_port = shared_page->vcpu_iodata[i].vp_eport;
        rc = ioctl(evtchn_fd, IOCTL_EVTCHN_BIND_INTERDOMAIN, &bind);
        if ( rc == -1 ) {
            fprintf(logfile, "bind interdomain ioctl error %d\n", errno);
            return NULL;
        }
        shared_page->vcpu_iodata[i].dm_eport = rc;
    }

    return env;
}
