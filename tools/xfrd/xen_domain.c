#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _XEN_XFR_STUB_
#include "dom0_defs.h"
#include "mem_defs.h"
#endif

#include "xen_domain.h"
#include "marshal.h"
#include "xdr.h"

#define MODULE_NAME "XFRD"
#define DEBUG 1
#include "debug.h"

/** Write domain state.
 *
 * At some point during this the domain is suspended, and then there's no way back.
 * Even if something later goes wrong we can't restart the domain.
 */
int xen_domain_snd(Conn *xend, IOStream *io, uint32_t dom, char *vmconfig, int vmconfig_n){
    int err = 0;
    char buf[1024];
    int n, k, d, buf_n;
    dprintf("> dom=%d\n", dom);
#ifdef _XEN_XFR_STUB_
    err = marshal_uint32(io, dom);
    if(err) goto exit;
    err = marshal_string(io, vmconfig, vmconfig_n);
    if(err) goto exit;
    n = 32 * 1024 * 1024;
    buf_n = sizeof(buf);
    err = marshal_uint32(io, n);
    for(k = 0; k < n; k += d){
        d = n - k;
        if(d > buf_n) d = buf_n;
        err = marshal_bytes(io, buf, d);
        if(err) goto exit;
        //dprintf("> k=%d n=%d\n", k, n);
    }
    
  exit:
#else 
#endif   
    dprintf("< err=%d\n", err);
    return err;
}

/** Receive domain state.
 * Create a new domain and store the received state into it.
 */
int xen_domain_rcv(IOStream *io, uint32_t *dom, char **vmconfig, int *vmconfig_n){
    int err = 0;
    char buf[1024];
    int n, k, d, buf_n;
    dprintf(">\n");
#ifdef _XEN_XFR_STUB_
    err = unmarshal_uint32(io, dom);
    if(err) goto exit;
    err = unmarshal_new_string(io, vmconfig, vmconfig_n);
    if(err) goto exit;
    err = unmarshal_uint32(io, &n);
    buf_n = sizeof(buf);
    for(k = 0; k < n; k += d){
        d = n - k;
        if(d > buf_n) d = buf_n;
        err = unmarshal_bytes(io, buf, d);
        if(err) goto exit;
        //dprintf("> k=%d n=%d\n", k, n);
    }
  exit:
#else    
#endif   
    dprintf("< err=%d\n", err);
    return err;
}

/** Configure a new domain. Talk to xend. Use libcurl?
 */
int xen_domain_configure(uint32_t dom, char *vmconfig, int vmconfig_n){
    int err = 0;
    dprintf(">\n");
#ifdef _XEN_XFR_STUB_
#else    
#endif   
    dprintf("< err=%d\n", err);
    return err;
}
