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
#undef DEBUG
#include "debug.h"

int domain_suspend(void *data, u32 dom){
    int err = 0;
    Conn *xend = data;

    dprintf("> dom=%lu data=%p\n", dom, data);
    err = xfr_vm_suspend(xend, dom);
    dprintf("< err=%d\n", err);
    return err;
}

int domain_configure(void *data, u32 dom, char *vmconfig, int vmconfig_n){
    return xen_domain_configure(dom, vmconfig, vmconfig_n);
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
int xen_domain_snd(Conn *xend, IOStream *io,
                   uint32_t dom,
                   char *vmconfig, int vmconfig_n,
                   int live, int resource){
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
    err = domain_suspend(xend, dom);
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
    if(live){
        ioctxt->flags |= XCFLAGS_LIVE;
    }
    ioctxt->resource = resource;
    err = xc_linux_save(xcinit(), ioctxt);
#endif   
    dprintf("< err=%d\n", err);
    return err;
}

/** Receive domain state.
 * Create a new domain and store the received state into it.
 */
int xen_domain_rcv(IOStream *io,
                   uint32_t *dom,
                   char **vmconfig, int *vmconfig_n,
                   int *configured){
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
    ioctxt->configure = domain_configure;
    if ( !*configured )
        ioctxt->flags |= XCFLAGS_CONFIGURE;

    err = xc_linux_restore(xcinit(), ioctxt);
    *dom = ioctxt->domain;
    *vmconfig = ioctxt->vmconfig;
    *vmconfig_n = ioctxt->vmconfig_n;
    *configured = (ioctxt->flags & XCFLAGS_CONFIGURE);
#endif   
    dprintf("< err=%d\n", err);
    return err;
}

#include <curl/curl.h>
#include "http.h"

/** Flag indicating whether we need to initialize libcurl. 
 */
static int do_curl_global_init = 1;

/** Get a curl handle, initializing libcurl if needed.
 *
 * @return curl handle
 */
static CURL *curlinit(void){
    if(do_curl_global_init){
        do_curl_global_init = 0;
        // Stop libcurl using the proxy. There's a curl option to
        // set the proxy - but no option to defeat it.
        unsetenv("http_proxy");
        curl_global_init(CURL_GLOBAL_ALL);
    }
    return curl_easy_init();
}

/** Curl debug function.
 */
int curldebug(CURL *curl, curl_infotype ty, char *buf, size_t buf_n, void *data){
    printf("%*s\n", buf_n, buf);
    return 0;
}

/** Setup a curl handle with a url.
 * Creates the url by formatting 'fmt' and the remaining arguments.
 *
 * @param pcurl return parameter for the curl handle
 * @param url url buffer
 * @param url_n size of url
 * @param fmt url format string, followed by parameters
 * @return 0 on success, error code otherwise
 */
static int curlsetup(CURL **pcurl, struct curl_slist **pheaders, char *url, int url_n, char *fmt, ...){
    int err = 0;
    va_list args;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    int n = 0;

    curl = curlinit();
    if(!curl){
        eprintf("> Could not init libcurl\n");
        err = -ENOMEM;
        goto exit;
    }
    url_n -= 1;
    va_start(args, fmt);
    n = vsnprintf(url, url_n, fmt, args);
    va_end(args);
    if(n <= 0 || n >= url_n){
        err = -ENOMEM;
        eprintf("> Out of memory in url\n");
        goto exit;
    }
    dprintf("> url=%s\n", url);
#if DEBUG
    // Verbose.
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    // Call the debug function on data received.
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curldebug);
#else
    // No progress meter.
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    // Completely quiet.
    curl_easy_setopt(curl, CURLOPT_MUTE, 1);
#endif
    // Set the URL.
    curl_easy_setopt(curl, CURLOPT_URL, url);

    headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
  exit:
    if(err && curl){
        curl_easy_cleanup(curl);
        curl = NULL;
    }
    *pcurl = curl;
    if (pheaders)
	*pheaders = headers;
    return err;
}

static void curlcleanup(CURL **pcurl, struct curl_slist **pheaders){
    if (*pcurl)
	curl_easy_cleanup(*pcurl);
    if (*pheaders)
	curl_slist_free_all(*pheaders);
    *pcurl = NULL;
    *pheaders = NULL;
}
/** Make the http request stored in the curl handle and get
 *  the result code from the curl code and the http return code.
 *
 * @param curl curl handle
 * @return 0 for success, error code otherwise
 */
int curlresult(CURL *curl){
    int err = 0;
    CURLcode curlcode = 0;
    long httpcode = 0;

    curlcode = curl_easy_perform(curl);
    if(curlcode){
        eprintf("> curlcode=%d\n", curlcode);
        err = -EINVAL;
        goto exit;
    }
    curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &httpcode);
    if(httpcode != HTTP_OK){
        eprintf("> httpcode=%d\n", (int)httpcode);
        err = -EINVAL;
        goto exit;
    }
  exit:
    return err;
}

/** Get xend to list domains.
 * We use this to force xend to refresh its domain list.
 *
 * @return 0 on success, error code otherwise
 */
int xen_domain_ls(void){
    int err = 0;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char url[128] = {};
    int url_n = sizeof(url);

    dprintf(">\n");
    err = curlsetup(&curl, &headers, url, url_n, "http://localhost:%d/xend/domain", XEND_PORT);
    if(err) goto exit;
    err = curlresult(curl);
  exit:
    curlcleanup(&curl, &headers);
    dprintf("< err=%d\n", err);
    return err;
}

/** Get xend to configure a new domain.
 *
 * @param dom domain id
 * @param vmconfig configuration string
 * @param vmconfig_n length of vmconfig
 * @return 0 on success, error code otherwise
 */
int xen_domain_configure(uint32_t dom, char *vmconfig, int vmconfig_n){
    int err = 0;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char url[128] = {};
    int url_n = sizeof(url);
    struct curl_httppost *form = NULL, *last = NULL;
    CURLFORMcode formcode = 0;

    dprintf("> dom=%u\n", dom);
    // List domains so that xend will update its domain list and notice the new domain.
    xen_domain_ls();

    err = curlsetup(&curl, &headers, url, url_n, "http://localhost:%d/xend/domain/%u", XEND_PORT, dom);
    if(err) goto exit;

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
        err = -EINVAL;
        goto exit;
    }
    // POST the form.
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, form);
    err = curlresult(curl);
  exit:
    curlcleanup(&curl, &headers);
    if(form) curl_formfree(form);
    dprintf("< err=%d\n", err);
    return err;
}

/** Get xend to unpause a domain.
 *
 * @param dom domain id
 * @return 0 on success, error code otherwise
 */
int xen_domain_unpause(uint32_t dom){
    int err = 0;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char url[128] = {};
    int url_n = sizeof(url);
    struct curl_httppost *form = NULL, *last = NULL;
    CURLFORMcode formcode = 0;

    dprintf("> dom=%u\n", dom);

    err = curlsetup(&curl, &headers, url, url_n, "http://localhost:%d/xend/domain/%u", XEND_PORT, dom);
    if(err) goto exit;

    // Op field.
    formcode = curl_formadd(&form, &last,
                            CURLFORM_COPYNAME,     "op",
                            CURLFORM_COPYCONTENTS, "unpause",
                            CURLFORM_END);
    if(formcode){
        eprintf("> Error adding op field.\n");
        err = -EINVAL;
        goto exit;
    }
    // POST the form.
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, form);
    err = curlresult(curl);
  exit:
    curlcleanup(&curl, &headers);
    if(form) curl_formfree(form);
    dprintf("< err=%d\n", err);
    return err;
}
