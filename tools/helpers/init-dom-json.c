#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <xenctrl.h>
#include <libxl.h>

int gen_stub_json_config(uint32_t domid, libxl_uuid *uuid)
{
    int rc = 1;
    xentoollog_logger_stdiostream *logger;
    libxl_ctx *ctx;
    libxl_domain_config dom_config;
    libxl_dominfo dominfo;
    char *json = NULL;

    logger = xtl_createlogger_stdiostream(stderr, XTL_ERROR, 0);
    if (!logger)
        return 1;

    if (libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0,
                        (xentoollog_logger *)logger)) {
        fprintf(stderr, "cannot init libxl context\n");
        goto outlog;
    }

    libxl_domain_config_init(&dom_config);

    libxl_dominfo_init(&dominfo);
    if (libxl_domain_info(ctx, &dominfo, domid)) {
        fprintf(stderr, "cannot get domain type\n");
        goto outdispose;
    }

    /* Generate stub JSON config. */
    dom_config.c_info.type = (dominfo.domain_type == LIBXL_DOMAIN_TYPE_HVM)
                             ? LIBXL_DOMAIN_TYPE_PVH : LIBXL_DOMAIN_TYPE_PV;
    libxl_domain_build_info_init_type(&dom_config.b_info,
                                      dom_config.c_info.type);

    if (uuid && !libxl_uuid_is_nil(uuid))
        libxl_uuid_copy(ctx, &dom_config.c_info.uuid, uuid);

    json = libxl_domain_config_to_json(ctx, &dom_config);
    /* libxl-json format requires the string ends with '\0'. Code
     * snippet taken from libxl.
     */
    rc = libxl_userdata_store(ctx, domid, "libxl-json",
                              (const uint8_t *)json,
                              strlen(json) + 1 /* include '\0' */);
    if (rc)
        fprintf(stderr, "cannot store stub json config for domain %u\n", domid);

outdispose:
    libxl_dominfo_dispose(&dominfo);
    libxl_domain_config_dispose(&dom_config);
    free(json);
    libxl_ctx_free(ctx);
outlog:
    xtl_logger_destroy((xentoollog_logger *)logger);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
