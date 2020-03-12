#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <xenctrl.h>
#include <xenstore.h>
#include <libxl.h>

#include "init-dom-json.h"

#define DOMNAME_PATH   "/local/domain/0/name"
#define DOMID_PATH     "/local/domain/0/domid"

static int clear_domid_history(void)
{
    int rc = 1;
    xentoollog_logger_stdiostream *logger;
    libxl_ctx *ctx;

    logger = xtl_createlogger_stdiostream(stderr, XTL_ERROR, 0);
    if (!logger)
        return 1;

    if (libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0,
                        (xentoollog_logger *)logger)) {
        fprintf(stderr, "cannot init libxl context\n");
        goto outlog;
    }

    if (!libxl_clear_domid_history(ctx))
        rc = 0;

    libxl_ctx_free(ctx);

outlog:
    xtl_logger_destroy((xentoollog_logger *)logger);
    return rc;
}

int main(int argc, char **argv)
{
    int rc;
    struct xs_handle *xsh = NULL;
    xc_interface *xch = NULL;
    char *domname_string = NULL, *domid_string = NULL;
    libxl_uuid uuid;

    /* Accept 0 or 1 argument */
    if (argc > 2) {
        fprintf(stderr, "too many arguments\n");
        rc = 1;
        goto out;
    }

    xsh = xs_open(0);
    if (!xsh) {
        perror("cannot open xenstore connection");
        rc = 1;
        goto out;
    }

    xch = xc_interface_open(NULL, NULL, 0);
    if (!xch) {
        perror("xc_interface_open() failed");
        rc = 1;
        goto out;
    }

    /* Sanity check: this program can only be run once. */
    domid_string = xs_read(xsh, XBT_NULL, DOMID_PATH, NULL);
    domname_string = xs_read(xsh, XBT_NULL, DOMNAME_PATH, NULL);
    if (domid_string && domname_string) {
        fprintf(stderr, "Dom0 is already set up\n");
        rc = 0;
        goto out;
    }

    libxl_uuid_clear(&uuid);

    /* If UUID is supplied, parse it. */
    if (argc == 2 && libxl_uuid_from_string(&uuid, argv[1])) {
        fprintf(stderr, "failed to parse UUID %s\n", argv[1]);
        rc = 1;
        goto out;
    }

    if (!libxl_uuid_is_nil(&uuid) &&
        xc_domain_sethandle(xch, 0, libxl_uuid_bytearray(&uuid))) {
        perror("failed to set Dom0 UUID");
        rc = 1;
        goto out;
    }

    rc = gen_stub_json_config(0, &uuid);
    if (rc)
        goto out;

    rc = clear_domid_history();
    if (rc)
        goto out;

    /* Write xenstore entries. */
    if (!xs_write(xsh, XBT_NULL, DOMID_PATH, "0", strlen("0"))) {
        fprintf(stderr, "cannot set domid for Dom0\n");
        rc = 1;
        goto out;
    }

    if (!xs_write(xsh, XBT_NULL, DOMNAME_PATH, "Domain-0",
                  strlen("Domain-0"))) {
        fprintf(stderr, "cannot set domain name for Dom0\n");
        rc = 1;
        goto out;
    }

    printf("Done setting up Dom0\n");

out:
    free(domid_string);
    free(domname_string);
    xs_close(xsh);
    xc_interface_close(xch);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
