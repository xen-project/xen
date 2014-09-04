#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <xenctrl.h>
#include <xenstore.h>
#include <libxl.h>

#define DOMNAME_PATH   "/local/domain/0/name"
#define DOMID_PATH     "/local/domain/0/domid"

static libxl_ctx *ctx;
static xentoollog_logger_stdiostream *logger;
static struct xs_handle *xsh;

static void ctx_alloc(void)
{
    if (libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0,
                        (xentoollog_logger *)logger)) {
        fprintf(stderr, "cannot init libxl context\n");
        exit(1);
    }
    xsh = xs_open(0);
    if (!xsh) {
        fprintf(stderr, "cannot open xenstore connection\n");
        exit(1);
    }
}

static void ctx_free(void)
{
    if (ctx) {
        libxl_ctx_free(ctx);
        ctx = NULL;
    }
    if (logger) {
        xtl_logger_destroy((xentoollog_logger *)logger);
        logger = NULL;
    }
    if (xsh) {
        xs_close(xsh);
        xsh = NULL;
    }
}

int main(int argc, char **argv)
{
    int rc;
    libxl_domain_config dom0_config;
    char *domname_string = NULL, *domid_string = NULL;
    char *json = NULL;;

    logger = xtl_createlogger_stdiostream(stderr, XTL_ERROR, 0);
    if (!logger) exit(1);

    atexit(ctx_free);

    ctx_alloc();

    libxl_domain_config_init(&dom0_config);

    /* Sanity check: this program can only be run once. */
    domid_string = xs_read(xsh, XBT_NULL, DOMID_PATH, NULL);
    domname_string = xs_read(xsh, XBT_NULL, DOMNAME_PATH, NULL);
    if (domid_string && domname_string) {
        fprintf(stderr, "Dom0 is already set up\n");
        rc = 0;
        goto out;
    }

    /* Generate stub JSON config. */
    dom0_config.c_info.type = LIBXL_DOMAIN_TYPE_PV;
    libxl_domain_build_info_init_type(&dom0_config.b_info,
                                      LIBXL_DOMAIN_TYPE_PV);

    json = libxl_domain_config_to_json(ctx, &dom0_config);
    /* libxl-json format requires the string ends with '\0'. Code
     * snippet taken from libxl.
     */
    rc = libxl_userdata_store(ctx, 0, "libxl-json",
                              (const uint8_t *)json,
                              strlen(json) + 1 /* include '\0' */);
    if (rc) {
        fprintf(stderr, "cannot store stub json config for Dom0\n");
        goto out;
    }

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
    libxl_domain_config_dispose(&dom0_config);
    free(domid_string);
    free(domname_string);
    free(json);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
