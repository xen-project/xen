#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _XEN_XFR_STUB_
typedef unsigned long u32;
#else
#include "xc.h"
#include "xc_io.h"
#endif

#include "xen_domain.h"
#include "marshal.h"
#include "xdr.h"
#include "xfrd.h"

#define MODULE_NAME "XFRD"
#define DEBUG 1
#include "debug.h"


int domain_suspend(u32 dom, void *data){
    int err = 0;
    Conn *xend = data;

    dprintf("> dom=%lu data=%p\n", dom, data);
    err = xfr_vm_suspend(xend, dom);
    dprintf("< err=%d\n", err);
    return err;
}

#ifndef _XEN_XFR_STUB_
static int xc_handle = 0;

int xcinit(void){
    if(xc_handle <= 0){
        xc_handle = xc_interface_open();
    }
    dprintf("< xc_handle=%d\n", xc_handle);
    return xc_handle;
}

void xcfini(void){
    if(xc_handle > 0){
        xc_interface_close(xc_handle);
        xc_handle = 0;
    }
}
#endif   

/** Write domain state.
 *
 * At some point during this the domain is suspended, and then there's no way back.
 * Even if something later goes wrong we can't restart the domain.
 */
int xen_domain_snd(Conn *xend, IOStream *io, uint32_t dom, char *vmconfig, int vmconfig_n){
    int err = 0;
#ifdef _XEN_XFR_STUB_
    char buf[1024];
    int n, k, d, buf_n;
    dprintf("> dom=%d\n", dom);
    err = marshal_uint32(io, dom);
    if(err) goto exit;
    err = marshal_string(io, vmconfig, vmconfig_n);
    if(err) goto exit;
    n = 32 * 1024 * 1024;
    n = 32 * 1024;
    buf_n = sizeof(buf);
    err = marshal_uint32(io, n);
    for(k = 0; k < n; k += d){
        d = n - k;
        if(d > buf_n) d = buf_n;
        err = marshal_bytes(io, buf, d);
        if(err) goto exit;
        dprintf("> k=%d n=%d\n", k, n);
    }
    
    dom = 99;
    err = domain_suspend(dom, xend);
    IOStream_close(io);
  exit:
#else 
    XcIOContext _ioctxt = {}, *ioctxt = &_ioctxt;
    ioctxt->domain = dom;
    ioctxt->io = io;
    ioctxt->info = iostdout;
    ioctxt->err = iostderr;
    ioctxt->data = xend;
    ioctxt->suspend = domain_suspend;
    ioctxt->vmconfig = vmconfig;
    ioctxt->vmconfig_n = vmconfig_n;

    err = xc_linux_save(xcinit(), ioctxt);
#endif   
    dprintf("< err=%d\n", err);
    return err;
}

/** Receive domain state.
 * Create a new domain and store the received state into it.
 */
int xen_domain_rcv(IOStream *io, uint32_t *dom, char **vmconfig, int *vmconfig_n){
    int err = 0;
#ifdef _XEN_XFR_STUB_
    char buf[1024];
    int n, k, d, buf_n;
    dprintf(">\n");
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
        dprintf("> k=%d n=%d\n", k, n);
    }
  exit:
#else    
    XcIOContext _ioctxt = {}, *ioctxt = &_ioctxt;
    dprintf(">\n");
    ioctxt->io = io;
    ioctxt->info = iostdout;
    ioctxt->err = iostderr;

    err = xc_linux_restore(xcinit(), ioctxt);
#endif   
    dprintf("< err=%d\n", err);
    return err;
}

#include <curl/curl.h>

static int do_curl_global_init = 1;

static CURL *curlinit(void){
    if(do_curl_global_init){
        do_curl_global_init = 0;
        curl_global_init(CURL_GLOBAL_ALL);
    }
    return curl_easy_init();
}

/** Configure a new domain. Talk to xend using libcurl.
 */
int xen_domain_configure(uint32_t dom, char *vmconfig, int vmconfig_n){
    int err = 0;
    CURL *curl = NULL;
    CURLcode curlcode = 0;
    char domainurl[128] = {};
    int domainurl_n = sizeof(domainurl) - 1;
    int n;
    struct curl_httppost *form = NULL, *last = NULL;
    CURLFORMcode formcode = 0;

    dprintf("> dom=%u\n", dom);
    curl = curlinit();
    if(!curl){
        eprintf("> Could not init libcurl\n");
        err = -ENOMEM;
        goto exit;
    }
    n = snprintf(domainurl, domainurl_n,
                 "http://localhost:%d/xend/domain/%u", XEND_PORT, dom);
    if(n <= 0 || n >= domainurl_n){
        err = -ENOMEM;
        eprintf("Out of memory in url.\n");
        goto exit;
    }
    // Config field - set from vmconfig.
    formcode = curl_formadd(&form, &last,
                            CURLFORM_COPYNAME,     "config",
                            CURLFORM_BUFFER,       "config",
                            CURLFORM_BUFFERPTR,    vmconfig,
                            CURLFORM_BUFFERLENGTH, vmconfig_n,
                            CURLFORM_CONTENTTYPE,  "application/octet-stream",
                            CURLFORM_END);
    if(formcode){
        eprintf("> Error adding config field.\n");
        goto exit;
    }
    // Op field.
    formcode = curl_formadd(&form, &last,
                            CURLFORM_COPYNAME,     "op",
                            CURLFORM_COPYCONTENTS, "configure",
                            CURLFORM_END);

    if(formcode){
        eprintf("> Error adding op field.\n");
        goto exit;
    }
    // No progress meter.
    //curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    // Completely quiet.
    //curl_easy_setopt(curl, CURLOPT_MUTE, 1);
    // Set the URL.
    curl_easy_setopt(curl, CURLOPT_URL, domainurl);
    // POST the form.
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, form);
    dprintf("> curl perform...\n");
#if 0 && defined(_XEN_XFR_STUB_)
    dprintf("> _XEN_XFR_STUB_ defined - not calling xend\n");
    curlcode = 0;
#else
    curlcode = curl_easy_perform(curl);
#endif
  exit:
    if(curl) curl_easy_cleanup(curl);
    if(form) curl_formfree(form);
    if(formcode){
        dprintf("> formcode=%d\n", formcode);
        err = -EINVAL;
    }
    if(curlcode){
        dprintf("> curlcode=%d\n", curlcode);
        err = -EINVAL;
    }
    dprintf("< err=%d\n", err);
    return err;
}
