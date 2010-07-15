/*
 * Copyright (C) 2009, Mukesh Rathor, Oracle Corp.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

/* This module is the main module for gdbsx implementation. gdbsx is a remote
 * gdbserver stub for xen. It facilitates debugging of xen guests. It also
 * prints vcpu contexts locally without remote gdb. */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>

#include "gx.h"


enum target_signal {
    TARGET_SIGNAL_INT = 2,
    TARGET_SIGNAL_TRAP = 5
};


/* At present, we don't support offlining VCPUs, or dynamic adding/removal
 * of them. As such, max_vcpu means active [0 - max_vcpuid] vcpus */
vcpuid_t max_vcpuid;        /* so max_vcpuid+1 vcpus overall */
int guest_bitness;          /* 32 or 64 */

const char host_name[] = "";

int gx_remote_dbg;          /* enable debug trace output for debugging */
uint64_t pgd3val;           /* value of init_mm.pgd[3] set by monitor gdb cmd */

static vcpuid_t current_vcpu;

/*
 * write regs received from remote gdb to guest 
 */
static void
gx_write_guest_regs(char *rbuf)
{
    union xg_gdb_regs gregs;
    int rc; 
    char *savrbuf = rbuf;
    int regsz = (guest_bitness == 32) ? sizeof(gregs.gregs_32) :
        sizeof(gregs.gregs_64);
    rbuf++;
    if (strlen(rbuf) != 2*regsz) {
        gxprt("ERROR: wrong sized register pkt received...\n"
              "Expected:%d got:%d\n", 2*regsz, strlen(rbuf));
    }
    gx_convert_ascii_to_int(rbuf, (char *)&gregs, regsz);

    rc = xg_regs_write(XG_GPRS, current_vcpu, &gregs, guest_bitness);
    if (rc) {
        gxprt("ERROR: failed to write regs. errno:%d\n", errno);
        savrbuf[0] ='\0';
        gx_reply_error(savrbuf);
    } else {
        gx_reply_ok(savrbuf);
    }
}

/*
 * read guest regs and send to remote gdb
 */
static void
gx_read_guest_regs(char *rbuf)
{
    union xg_gdb_regs gregs;
    int rc;

    rc = xg_regs_read(XG_GPRS, current_vcpu, &gregs, guest_bitness);
    if (rc) {
        gxprt("ERROR: failed to read regs. errno:%d\n", errno);
        rbuf[0] ='\0';
    } else {
        int sz = (guest_bitness == 32) ? sizeof(gregs.gregs_32) :
            sizeof(gregs.gregs_64);
        gx_convert_int_to_ascii((char *)&gregs, rbuf, sz);
    }
}

/* remote_buf: 'qRcmd,pgd3 c0ae9018\0'  (c0ae9018 may also be 0xc0ae9018) */
static void
_do_qRcmd_req(char *remote_buf)
{
    char buf[64], buf1[64];
    char *p = remote_buf + 6;
    int len = strlen(p)/2;        /* because "70" is one char "p" */

    gx_convert_ascii_to_int(p, buf, len);
    XGTRC("remote_buf:%s buf:%s\n", remote_buf, buf);

    if (strncmp(buf, "pgd3 ", 5) == 0) {
        char *endp;

        pgd3val = strtoull(buf+5, &endp, 16);
        XGTRC("buf+5:%s pgd3val:0x%llx\n", buf+5, pgd3val);

        if (*endp == '\0' && pgd3val > 0) {
            sprintf(buf1, "pgd3val set to: "XGF64"\n", pgd3val);
        } else {
            sprintf(buf1, "Invalid  pgd3val "XGF64"\n", pgd3val);
            pgd3val = 0;
        }
    } else {
        sprintf(buf1, "Bad monitor command\n");
    }
    gx_convert_int_to_ascii(buf1, remote_buf, strlen(buf1));
    return;
}

/* qSupported  qC qfThreadInfo qsThreadInfo qThreadExtraInfo,1  etc.. */
static void
process_q_request(char *remote_buf)
{
    /* send a list of tids: "m0,1,2,3l" */
    if (strcmp("qfThreadInfo", remote_buf) == 0) {
        vcpuid_t vid = 0;
        char *p = remote_buf;

        sprintf(p, "m%x", vid);        /* puts null char at the end */
        p = p + strlen(p);
        for (vid=1; vid <= max_vcpuid; vid++) {
            sprintf(p, ",%x", vid);
            p = p + strlen(p);
        }
        sprintf(p, "l");                /* puts null char at the end */
        return;
    }

    /* qSymbol works for init_mm, and not init_mm.pgd, hence we can't use
     * it at this time. instead use "monitor" in gdb */
    if (strncmp("qRcmd,", remote_buf, 6) == 0) {
        _do_qRcmd_req(remote_buf);
        return;
    }

    /* TBD : qThreadExtraInfo : send extra banner info  */

    remote_buf[0] = '\0';              /* nothing else supported for now */

    return;
}

/*
 * Set current thread/vcpu to : -1 all threads, 0 any thread, or given tid/vcpu
 * Even tho, 0 is a valid vcpu for us, it's OK as vcpu 0 is any vcpu 
 *   Eg.  Hc-1\0  Hc0\0  etc...
 */
static void
process_H_request(char *remote_buf)
{
    char ch1 = remote_buf[1];

    if (ch1 == 'c' || ch1 == 'g' || ch1 == 's') {
        vcpuid_t vcpu;

        /* we keep vcpu_id (which gdb thinks is tid) and 
         * gdb_id the same for simplicity */

        vcpu = strtoul(&remote_buf[2], NULL, 16);
        if (vcpu == -1) {
            vcpu = 0;
        }
        /* it doesn't matter to us: g, c, or s */
        current_vcpu = vcpu;
        gx_reply_ok(remote_buf);
    } else {
        /* Silently ignore so gdb can extend the protocol
         * without compatibility headaches */
        remote_buf[0] = '\0';
    }
}

/* read guest memory to send to remote gdb user */
static void
process_m_request(char *remote_buf)
{
    uint64_t addr;
    int len, remain;
    char *xbuf;

    gx_decode_m_packet(&remote_buf[1], &addr, &len);

    if ((xbuf=malloc(len+1)) == NULL) {
        gx_reply_error(remote_buf);
        return;
    }
    if ((remain=xg_read_mem(addr, xbuf, len, pgd3val)) != 0) {
        XGTRC("Failed read mem. addr:0x%llx len:%d remn:%d errno:%d\n",
              addr, len, remain, errno);
        gx_reply_error(remote_buf);
        free(xbuf);
        return;
    }
    gx_convert_int_to_ascii(xbuf, remote_buf, len);
    free(xbuf);
    return;
}

/* write guest memory */
static void
process_M_request(char *remote_buf)
{
    uint64_t addr;
    int len, remain;
    char *xbuf, *data_strtp;   /* where guest data actually starts */

    data_strtp = gx_decode_M_packet(&remote_buf[1], &addr, &len);

    if ((xbuf=malloc(len+1)) == NULL) {
        gx_reply_error(remote_buf);
        return;
    }
    gx_convert_ascii_to_int(data_strtp, xbuf, len);

    if ((remain=xg_write_mem(addr, xbuf, len, pgd3val)) != 0) {
        gxprt("Failed write mem. addr:0x%llx len:%d rem:%d errno:%d\n",
              addr, len, remain, errno);
        gx_reply_error(remote_buf);
    } else {
        gx_reply_ok(remote_buf);
    }
    free(xbuf);
    return;
}

/* Eg.: "vCont;c" "vCont;s:5" */
static void
process_v_cont_request(char *bufp)
{
    char *savbufp = bufp;

    bufp = bufp + 5;                   /* address of semicolon */

    if (*bufp == '\0' || *bufp != ';')
        goto errout;
    bufp++;
    if (*bufp == 'S' || *bufp == 'C')  /* we don't support signalling */
        goto errout;
#if 0
    if (*bufp == 'c') {
        if (*(bufp+1) != '\0')
            goto errout;       /* don't tolerate bad pkt */
        xg_resume(guest_bitness);  /* continue domain */

    } else if (*bufp == 's') {

        /* we don't support : step vcpuid. user must switch to the
         * thread/vcpu and then do step */
        bufp++;
        if (*bufp != '\0')
            goto errout;
        xg_step(current_vcpu, guest_bitness);
    }
#endif
    return;

 errout:
    savbufp[0] = '\0';
    gxprt("WARN: Bad v pkt: %s\n", savbufp);
    return;
}

static void
process_v_request(char *remote_buf)
{
    if (strncmp(remote_buf, "vCont;", 6) == 0) {
        process_v_cont_request(remote_buf);  /* valid request */
        return;
    }
    if (strncmp(remote_buf, "vCont?", 6) == 0) {
        /* tell remote gdb what we support : c and s */
        /* strcpy(remote_buf, "vCont;c;s"); */
        remote_buf[0] = '\0';
        return;
    }
    /* failed to understand the v packet */
    remote_buf[0] = '\0';
    return;
}

/* TBD: add watchpoint in future */
static int
watchpoint_stop(void)
{
    return 0;
}

#if 0
static char *
copy_mini_context32(char *rbuf, union xg_gdb_regs32 *regsp)
{
    *rbuf++ = gx_tohex((EBP_IDX >> 4) & 0xf);
    *rbuf++ = gx_tohex(EBP_IDX & 0xf);
    *rbuf++ = ':';
    rbuf = gx_convert_int_to_ascii(regsp->ebp, rbuf, 4);

    *rbuf++ = gx_tohex((ESP_IDX >> 4) & 0xf);
    *rbuf++ = gx_tohex(ESP_IDX & 0xf);
    *rbuf++ = ':';
    rbuf = gx_convert_int_to_ascii(regsp->esp, rbuf, 4);

    *rbuf++ = gx_tohex((EIP_IDX >> 4) & 0xf);
    *rbuf++ = gx_tohex(EIP_IDX & 0xf);
    *rbuf++ = ':';
    rbuf = gx_convert_int_to_ascii(regsp->eip, rbuf, 4);

    return rbuf;
}

static char *
copy_mini_context64(char *rbuf, union xg_gdb_regs64 *regsp)
{
    *rbuf++ = gx_tohex((RBP_IDX >> 4) & 0xf);
    *rbuf++ = gx_tohex(RBP_IDX & 0xf);
    *rbuf++ = ':';
    rbuf = gx_convert_int_to_ascii(regsp->ebp, rbuf, 4);

    *rbuf++ = gx_tohex((RSP_IDX >> 4) & 0xf);
    *rbuf++ = gx_tohex(RSP_IDX & 0xf);
    *rbuf++ = ':';
    rbuf = gx_convert_int_to_ascii(regsp->esp, rbuf, 4);

    *rbuf++ = gx_tohex((RIP_IDX >> 4) & 0xf);
    *rbuf++ = gx_tohex(RIP_IDX & 0xf);
    *rbuf++ = ':';
    rbuf = gx_convert_int_to_ascii(regsp->eip, rbuf, 4);

    return rbuf;
}

static char *
copy_mini_context(char *rbuf)
{
    union xg_gdb_regs regs;

    if (xg_regs_read(XG_GPRS, 0, &regs, guest_bitness)) {
        gxprt("WARN: Unable to get read regs. errno:%d\n", errno);
        return;
    }
    if (guest_bitness == 32)
        rbuf = copy_mini_context32(rbuf, &regs.u.gregs_32);
    else
        rbuf = copy_mini_context64(rbuf, &regs.u.gregs_64);
    return rbuf;    
}

#endif

/*
 * prepare reply for remote gdb as to why we stopped 
 */
static void
prepare_stop_reply(enum target_signal sig, char *buf, vcpuid_t vcpu)
{
    int nib;

    *buf++ = 'T';       /* we stopped because of a trap (SIGTRAP) */

    nib = ((sig & 0xf0) >> 4);
    *buf++ = gx_tohex(nib);
    nib = sig & 0x0f;
    *buf++ = gx_tohex(nib);

    /* TBD: check if we stopped because of watchpoint */
    if (watchpoint_stop()) {
        strncpy(buf, "watch:", 6);
        buf += 6;
        /* TBD: **/
    }
    sprintf(buf, "thread:%x;", vcpu);
    buf += strlen(buf);
    *buf++ = '\0';
}
/*
 * Indicate the reason the guest halted
 */
static void
process_reas_request(char *remote_buf, vcpuid_t vcpu)
{
    prepare_stop_reply(TARGET_SIGNAL_TRAP, remote_buf, vcpu);
}

/* continue request */
static void
process_c_request(char *remote_buf)
{
    enum target_signal sig;

    if ((current_vcpu=xg_resume_n_wait(guest_bitness)) == -1) {
        current_vcpu = 0;            /* default vcpu */
        sig = TARGET_SIGNAL_INT;
    } else
        sig = TARGET_SIGNAL_TRAP;

    prepare_stop_reply(sig, remote_buf, current_vcpu);
}

#if 0
/* insert a bp: Z#,addr,len : where # is 0 for software bp, 1 for hardware bp,
 *              2 is a write watchpoint, 3 is read watchpoint, 4 access watchpt
 *              We ignore len, it should always be 1.
 *  Eg: Z0,c0267d3a,1
 */
static void
process_Z_request(char *rbuf)
{
    char ch1 = rbuf[1];
    uint64_t gva;

    if (ch1 != '0') {
        gx_reply_error(rbuf);
        return;
    }
    gx_decode_zZ_packet(&rbuf[3], &gva);
    if (xg_set_bp(gva, ch1))
        gx_reply_error(rbuf);
    else
        gx_reply_ok(rbuf);
}

/* remove a bp */
static void
process_z_request(char *rbuf)
{
    char ch1 = rbuf[1];
    uint64_t gva;

    if (ch1 != '0') {
        gx_reply_error(rbuf);
        return;
    }
    gx_decode_zZ_packet(&rbuf[3], &gva);
    if (xg_rm_bp(gva, ch1))
        gx_reply_error(rbuf);
    else
        gx_reply_ok(rbuf);
}
#endif

static int
process_remote_request(char *remote_buf)   /* buffer received from remote gdb */
{
    char ch;
    int rc=0, i=0;

    XGTRC("E:%s curvcpu:%d\n", remote_buf, current_vcpu);

    ch = remote_buf[i++];
    switch(ch)
    {
    case 'q':
        process_q_request(remote_buf);
        break;

    case 'd':    /* print debug trace output */
        gx_remote_dbg = !gx_remote_dbg;
        printf("WARN: received d pkt:%s\n", remote_buf);
        remote_buf[0] = '\0';
        break;

    case 'D':
        gx_reply_ok(remote_buf);
        rc = 1;
        break;

    case '?':
        process_reas_request(remote_buf, 0);
        break;

    case 'H':
        process_H_request(remote_buf);
        break;

        /* send general registers to remote gdb */
    case 'g': 
        assert(current_vcpu != -1);
        gx_read_guest_regs(remote_buf);
        break;

        /* receive general regs from remote gdb */
    case 'G':
        assert(current_vcpu != -1);
        gx_write_guest_regs(remote_buf);
        break;

        /* read guest memory and send to remote gdb */
    case 'm':
        process_m_request(remote_buf);
        break;

    case 'M':
        process_M_request(remote_buf);
        break;

    case 'C':
        printf("WARN: C pkt: %s\n", remote_buf);
        remote_buf[0] = '\0';
        break;

    case 'S':
        printf("WARN: S pkt:%s\n", remote_buf);
        remote_buf[0] = '\0';
        break;

    case 'c':
        process_c_request(remote_buf);     /* continue request */
        break;

    case 's':                              /* single step */
        if (xg_step(current_vcpu, guest_bitness) != 0) {
            remote_buf[0] = '\0';
        } else {
            prepare_stop_reply(TARGET_SIGNAL_TRAP, remote_buf, 
                               current_vcpu);
        }
        break;

#if 0
    case 'Z':
        process_Z_request(remote_buf);     /* insert a bp */
        break;
              
    case 'z':
        process_z_request(remote_buf);     /* remove a bp */
        break;
#endif
    case 'k':      /* kill inferior */
        printf("WARN: k pkt:%s\n", remote_buf);
        remote_buf[0] = '\0';
        break;

    case 'T':      /* find out if thread is alive */
        gx_reply_ok(remote_buf);   /* no vcpu offling supported yet */
        break;

    case 'R':  /* TBD: restart gdbserver program */
        /* Restarting the inferior is only supported in the
         * extended protocol.  */
        remote_buf[0] = '\0';
        break;

    case 'v':
        process_v_request(remote_buf);
        break;

    default:
        /* It is a request we don't understand.  Respond with an
         * empty packet so that gdb knows that we don't support this
         * request.  */
        remote_buf[0] = '\0';
        break;

    }   /* end of switch(ch) */

    XGTRC("X:%s curvcpu:%d\n", remote_buf, current_vcpu);
    return rc;
}

static void
gdbsx_usage_exit(void)
{
    printf ("Usage 1: gdbsx -a domid <32|64> PORT [-d]\n"
            "         PORT to listen for a TCP connection.\n"
            "         Eg. gdbsx -a 3 32 9999\n\n");
    printf("Usage 2: gdbsx -c domid <32|64> [vcpu#] [-d]\n");
    printf("         to dump vcpu context(s) for given domid\n\n");
    exit(1);
}

static void
check_usage_n_stuff(int argc, char **argv, domid_t *domid_p, vcpuid_t *vp)
{
    char *arg_end;

    if (strcmp(argv[argc-1], "-d")==0) {
        xgtrc_on = 1;       /* debug trace on */
        argc--;
    }
    if (argc < 4 || (strcmp(argv[1], "-h") == 0) || 
        (strcmp(argv[1], "-a")==0 && argc < 5)) {
        gdbsx_usage_exit();
    }
    if (argc > 5  || 
        (*domid_p=strtoul(argv[2], &arg_end, 10)) == 0  ||
        *arg_end != '\0'  || 
        *domid_p == 0  ||
        (guest_bitness=strtoul(argv[3], &arg_end, 10)) == 0 ||
        *arg_end != '\0'  || 
        (guest_bitness != 32 && guest_bitness != 64)) {

        gdbsx_usage_exit();
    }
    *vp = -1;        /* assume all VCPUs */
    if (strcmp(argv[1], "-c")==0 && argc >= 5) {
        *vp = strtoul(argv[4], &arg_end, 10);
        if (*arg_end != '\0') {
            gdbsx_usage_exit();
        }
    }
}

static void
initialize(char **rbufpp)
{
#define BUFSIZE 4096

    /* allocate buffer used to communicate back and forth with remote gdb */
    /* size should be big enough to hold all registers + extra */
    if ((*rbufpp=malloc(BUFSIZE)) == NULL) {
        gxprt("ERROR: can't malloc %d bytes. errno:%d\n", 
              BUFSIZE, errno);
        exit(3);
    }
    signal(SIGIO, SIG_IGN);   /* default action is TERM */
}


int
main(int argc, char *argv[])
{
    char *remote_buf;
    domid_t domid = 0;
    vcpuid_t vcpuid;
    int exit_rc = 0;

    check_usage_n_stuff(argc, argv, &domid, &vcpuid);

    if (xg_init() == -1) {
        gxprt("ERROR: failed to initialize errno:%d\n", errno);
        exit(1);
    }
    if ((max_vcpuid=xg_attach(domid, guest_bitness)) == -1) {
        gxprt("ERROR: failed to attach to domain:%d errno:%d\n",
              domid, errno);
        exit(1);
    }
    if (strcmp(argv[1], "-c")==0) {
        if (vcpuid != -1 && vcpuid > max_vcpuid) {    /* just got set */
            printf("gdbsx: Invalid VCPU id:%d\n", vcpuid);
            xg_detach_deinit();
            gdbsx_usage_exit();
        }
        exit_rc = gx_local_cmd(domid, vcpuid);
        xg_detach_deinit();
        return exit_rc;               /* EXIT */
    }

    initialize(&remote_buf);

    /* we have the guest paused at this point, ready for debug. wait for
     * connection from remote gdb */
    if (gx_remote_open(argv[4]) == -1) {
        xg_detach_deinit();
        return 1;
    }

    /* we've a gdb connection at this point, process requests */
    while(gx_getpkt(remote_buf) > 0) {
        if ((exit_rc=process_remote_request(remote_buf)))
            break;
        if (gx_putpkt(remote_buf) == -1) {
            exit_rc = 1;
            break;
        }
    }
    /* unpause and let the guest continue */
    gxprt("Detaching from guest\n");
    xg_detach_deinit();

    if (exit_rc == 0) {
        gxprt("Exiting.. Remote side has terminated connection\n");
    }
    gx_remote_close();
    return exit_rc;
}
