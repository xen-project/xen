/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include "ofh.h"
#include <stdarg.h>
#include <xen/lib.h>

/*
 * 6.3.1 Access to the client interface functions
 * This is the spec'd maximum
 */
#define PFW_MAXSRVCLEN 31

static u32 ofh_maxsrvclen;

extern s32 debug(const char *fmt, ...);

s32 debug(const char *fmt, ...)
{
    s32 sz;
    va_list ap;
    char buf[512];
    va_start(ap, fmt);
    sz = vsnprintf(buf, 512, fmt, ap);
    va_end(ap);
    ofh_cons_write(buf, sz, &sz);

    return sz;
}



void
assprint(const char *expr, const char *file, int line, const char *fmt, ...)
{
    char a[15];

    a[0]  = '\n';
    a[1]  = '\n';
    a[2]  = 'O';
    a[3]  = 'F';
    a[4]  = 'H';
    a[5]  = ':';
    a[6]  = 'A';
    a[7]  = 'S';
    a[8]  = 'S';
    a[9]  = 'E';
    a[10] = 'R';
    a[11] = 'T';
    a[12] = '!';
    a[13] = '\n';
    a[14] = '\n';

    s32 actual;
    u32 t = 1;
    volatile u32 *tp = &t;

    (void)expr; (void)file; (void)line; (void)fmt;

    ofh_cons_write(a, sizeof (a), &actual);

    /* maybe I can break out of this loop manually (like with a
     * debugger) */
    while (*tp) {
        continue;
    }
}

/*
 * we use elf hash since it is pretty standard
 */
static u32
of_hash(const char *s)
{
    u32 hash = 0;
    u32 hnib;

    if (s != NULL) {
        while (*s != '\0') {
            hash = (hash << 4) + *s++;
            hnib = hash & 0xf0000000UL;
            if (hnib != 0) {
                hash ^= hnib >> 24;
            }
            hash &= ~hnib;
        }
    }
    return hash;
}

static void
ofh_service_init(ulong b)
{
    ulong sz;
    int i;
    int j = 0;
    struct ofh_srvc *o;
    struct ofh_srvc *ofs[] = {
        DRELA(&ofh_srvc[0], b),
        DRELA(&ofh_isa_srvc[0], b),
        NULL
    };

    j = 0;
    while (ofs[j] != NULL) {
        /* find the maximum string length for services */
        o = &ofs[j][0];
        while (o->ofs_name != NULL) {
            const char *n;

            n = DRELA(&o->ofs_name[0], b);
            /* fix it up so we don't have to fix it anymore */
            o->ofs_name = n;

            sz = strlen(n);
            if (sz > *DRELA(&ofh_maxsrvclen, b)) {
                *DRELA(&ofh_maxsrvclen, b) = sz;
            }
            o->ofs_hash =
                of_hash(n);
            ++i;
            ++o;
        }
        ++j;
    }
}


static void
ofh_cpu_init(ofdn_t chosen, ulong b)
{
    static struct ofh_ihandle _ih_cpu_0;
    void *mem = ofd_mem(b);
    u32 ih = DRELA((ulong)&_ih_cpu_0, b);
    struct ofh_ihandle *ihp = (struct ofh_ihandle *)((ulong)ih);
    const char *cpu_type = DRELA((const char*)"cpu",b);

    ofdn_t cpu = ofd_node_find_by_prop(mem, OFD_ROOT,
                                       DRELA((const char*)"device_type",b),
                                       cpu_type, 4);
    ihp->ofi_node = cpu;
    ofd_prop_add(mem, chosen, DRELA((const char *)"cpu", b),
                 &ih, sizeof (ih));
}
static s32
mmu_translate(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    /* FIXME: need a little more here */
    nargs = nargs;
    nrets = nrets;
    argp = argp;
    retp = retp;
    b = b;
    return OF_SUCCESS;
}

static void
ofh_mmu_init(ofdn_t chosen, ulong b)
{
    static struct ofh_methods _mmu_methods[] = {
        { "translate", mmu_translate },
        { NULL, NULL},
    };
    static struct ofh_ihandle _ih_mmu = {
        .ofi_methods = _mmu_methods,
    };
    void *mem = ofd_mem(b);
    u32 ih = DRELA((ulong)&_ih_mmu, b);

    ofd_prop_add(mem, chosen, DRELA((const char *)"mmu", b),
                 &ih, sizeof (ih));
}

static void
ofh_chosen_init(ulong b)
{
    ofdn_t ph;
    void *mem = ofd_mem(b);

    ph = ofd_node_find(mem, DRELA((const char *)"/chosen", b));

    ofh_vty_init(ph, b);
    ofh_cpu_init(ph, b);
    ofh_mmu_init(ph, b);
}

static void
ofh_options_init(ulong b)
{
    void *mem = ofd_mem(b);
    ofdn_t options;
    u32 size = 1 << 20;
    u32 base = b;
    char buf[20];
    int i;


    /* fixup the ihandle */
    options = ofd_node_find(mem,
                            DRELA((const char *)"options", b));

    i = snprintf(buf, sizeof (buf), "0x%x", base);
    ofd_prop_add(mem, options, DRELA((const char *)"real-base", b),
                 buf, i);

    i = snprintf(buf,sizeof (buf), "0x%x", size);
    ofd_prop_add(mem, options, DRELA((const char *)"real-size", b),
                 buf, i);
}

static void
ofh_init(ulong b)
{
    ulong sz = (ulong)_end - (ulong)__bss_start;
    /* clear bss */
    memset(__bss_start + b, 0, sz);

    ofh_service_init(b);
    ofh_chosen_init(b);
    ofh_options_init(b);
}

static ofh_func_t *
ofh_lookup(const char *service, ulong b)
{
    int j;
    u32 hash;
    struct ofh_srvc *o;
    struct ofh_srvc *ofs[] = {
        DRELA(&ofh_srvc[0], b),
        DRELA(&ofh_isa_srvc[0], b),
        NULL
    };
    u32 sz;

    sz = *DRELA(&ofh_maxsrvclen, b);

    if (strnlen(service, sz + 1) > sz) {
        return NULL;
    }

    hash = of_hash(service);

    j = 0;
    while (ofs[j] != NULL) {
        /* yes this could be quicker */
        o = &ofs[j][0];
        while (o->ofs_name != NULL) {
            if (o->ofs_hash == hash) {
                const char *n = o->ofs_name;
                if (strcmp(service, n) == 0) {
                    return o->ofs_func;
                }
            }
            ++o;
        }
        ++j;
    }
    return NULL;
}

s32
ofh_nosup(u32 nargs __attribute__ ((unused)),
        u32 nrets __attribute__ ((unused)),
        s32 argp[] __attribute__ ((unused)),
        s32 retp[] __attribute__ ((unused)),
        ulong b __attribute__ ((unused)))
{
    return OF_FAILURE;
}

s32
ofh_test_method(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 2) {
        if (nrets == 1) {
            s32 *ap = DRELA(&ofh_active_package, b);
            u32 service = (s32)argp[0];
            const char *method = (const char *)(ulong)argp[1];
            s32 *stat = &retp[0];

            (void)ap; (void)service; (void)method;

            *stat = 0;
            /* we do not do this yet */
            return OF_FAILURE;
        }
    }
    return OF_FAILURE;
}
extern u32 _ofh_inited[0];
extern u32 _ofh_lastarg[0];

s32
ofh_handler(struct ofh_args *args, ulong b)
{
    u32 *inited = (u32 *)DRELA(&_ofh_inited[0],b);
    u32 *lastarg = (u32 *)DRELA(&_ofh_lastarg[0],b);
    ofh_func_t *f;

    if (*inited == 0) {
        ofh_init(b);

        if ((ulong)ofd_mem(b) < (ulong)_end + b) {
            static const char msg[] = "PANIC: OFD and BSS collide\n";
            s32 dummy;

            ofh_cons_write(DRELA(&msg[0], b), sizeof (msg), &dummy);
            for (;;);
        }

        *inited = 1;
    }

    *lastarg = (ulong)args;

    f = ofh_lookup((char *)((ulong)args->ofa_service), b);

    if (f == ((ofh_func_t *)~0UL)) {
        /* do test */
        if (args->ofa_nargs == 1) {
            if (args->ofa_nreturns == 1) {
                char *name = (char *)(ulong)args->ofa_args[0];
                if (ofh_lookup(name, b) != NULL) {
                    args->ofa_args[args->ofa_nargs] =
                        OF_SUCCESS;
                    return OF_SUCCESS;
                }
            }
        }
        return OF_FAILURE;

    } else if (f != NULL) {
        return leap(args->ofa_nargs,
                    args->ofa_nreturns,
                    args->ofa_args,
                    &args->ofa_args[args->ofa_nargs],
                    b, f);
    }
    return OF_FAILURE;
}

/*
 * The following code exists solely to run the handler code standalone
 */
void
__ofh_start(void)
{
    s32 ret;
    u32 of_stdout;
    u32 ihandle;
    char buf[1024];
    u32 args_buf[sizeof (struct ofh_args) + (sizeof (u32) * 10)];
    struct ofh_args *args;

    args = (struct ofh_args *)args_buf;

    args->ofa_service = (u32)"finddevice";
    args->ofa_nargs     = 1;
    args->ofa_nreturns  = 1;
    args->ofa_args[0]   = (u32)"/";
    args->ofa_args[1]   = -1;
    ret = ofh_start(args);

    if (ret == OF_SUCCESS) {
        args->ofa_service   = (u32)"finddevice";
        args->ofa_nargs     = 1;
        args->ofa_nreturns  = 1;
        args->ofa_args[0]   = (u32)"/chosen";
        args->ofa_args[1]   = -1;
        ret = ofh_start(args);
    }

    if (ret == OF_SUCCESS) {
        u32 phandle = args->ofa_args[1];

        args->ofa_service   = (u32)"getprop";
        args->ofa_nargs     = 4;
        args->ofa_nreturns  = 1;
        args->ofa_args[0]   = phandle;
        args->ofa_args[1]   = (ulong)"stdout";
        args->ofa_args[2]   = (ulong)&of_stdout;
        args->ofa_args[3]   = sizeof(of_stdout);
        args->ofa_args[4]   = -1;
        ret = ofh_start(args);
    }

    ihandle = *(u32 *)((ulong)args->ofa_args[2]);

    if (ret == OF_SUCCESS) {
        /* instance to path */
        args->ofa_service   = (u32)"instance-to-path";
        args->ofa_nargs     = 3;
        args->ofa_nreturns  = 1;
        args->ofa_args[0]   = ihandle;
        args->ofa_args[1]   = (ulong)buf;
        args->ofa_args[2]   = sizeof (buf);
        args->ofa_args[3]   = -1;
        ret = ofh_start(args);

    }

    if (ret == OF_SUCCESS) {
        /* open rtas */
        args->ofa_service   = (u32)"open";
        args->ofa_nargs     = 1;
        args->ofa_nreturns  = 1;
        args->ofa_args[0]   = (u32)"/rtas";
        ret = ofh_start(args);
        if (ret == OF_SUCCESS) {
            u32 ir = args->ofa_args[1];
            args->ofa_service   = (u32)"call-method";
            args->ofa_nargs     = 3;
            args->ofa_nreturns  = 2;
            args->ofa_args[0]   = (ulong)"instantiate-rtas";
            args->ofa_args[1]   = ir;
            args->ofa_args[2]   = (ulong)buf;

            ret = ofh_start(args);
        }
    }

    if (ret == OF_SUCCESS) {
        const char msg[] = "This is a test";
        u32 msgsz = sizeof(msg) - 1; /* Includes \0 */

        args->ofa_service   = (u32)"write";
        args->ofa_nargs     = 3;
        args->ofa_nreturns  = 1;
        args->ofa_args[0]   = ihandle;
        args->ofa_args[1]   = (ulong)msg;
        args->ofa_args[2]   = msgsz;
        args->ofa_args[3]   = -1;
        ret = ofh_start(args);
    }

}
