#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxlu_internal.h"

static const char *vif_bytes_per_sec_re = "^[0-9]+[GMK]?[Bb]/s$";
static const char *vif_internal_usec_re = "^[0-9]+[mu]?s?$";

static void xlu__vif_err(XLU_Config *cfg, const char *msg, const char *rate) {
    fprintf(cfg->report,
            "%s: config parsing error in vif: %s in `%s'\n",
            cfg->config_source, msg, rate);
}

static int vif_parse_rate_bytes_per_sec(XLU_Config *cfg, const char *bytes,
                                        uint64_t *bytes_per_sec)
{
    regex_t rec;
    uint64_t tmp = 0;
    const char *p;
    int rc = 0;

    regcomp(&rec, vif_bytes_per_sec_re, REG_EXTENDED|REG_NOSUB);
    if (regexec(&rec, bytes, 0, NULL, 0)) {
        xlu__vif_err(cfg, "invalid rate", bytes);
        rc = EINVAL;
        goto out;
    }

    p = bytes;
    tmp = strtoull(p, (char**)&p, 0);
    if (tmp == 0 || tmp > UINT32_MAX || errno == ERANGE) {
        xlu__vif_err(cfg, "rate overflow", bytes);
        rc = EOVERFLOW;
        goto out;
    }

    if (*p == 'G')
       tmp *= 1000 * 1000 * 1000;
    else if (*p == 'M')
       tmp *= 1000 * 1000;
    else if (*p == 'K')
       tmp *= 1000;
    if (*p == 'b' || *(p+1) == 'b')
       tmp /= 8;

    *bytes_per_sec = tmp;

out:
    regfree(&rec);
    return rc;
}

static int vif_parse_rate_interval_usecs(XLU_Config *cfg, const char *interval,
                                         uint32_t *interval_usecs)
{
    regex_t rec;
    uint64_t tmp = 0;
    const char *p;
    int rc = 0;

    regcomp(&rec, vif_internal_usec_re, REG_EXTENDED|REG_NOSUB);
    if (regexec(&rec, interval, 0, NULL, 0)) {
        xlu__vif_err(cfg, "invalid replenishment interval", interval);
        rc = EINVAL;
        goto out;
    }

    p = interval;
    tmp = strtoull(p, (char**)&p, 0);
    if (tmp == 0 || tmp > UINT32_MAX || errno == ERANGE) {
        xlu__vif_err(cfg, "replenishment interval overflow", interval);
        rc = EOVERFLOW;
        goto out;
    }

    if (*p == 's' || *p == '\0')
        tmp *= 1000 * 1000;
    else if (*p == 'm')
        tmp *= 1000;

    if (tmp > UINT32_MAX) {
        xlu__vif_err(cfg, "replenishment interval overflow", interval);
        rc = EOVERFLOW;
        goto out;
    }

    *interval_usecs = (uint32_t) tmp;

out:
    regfree(&rec);
    return rc;
}

int xlu_vif_parse_rate(XLU_Config *cfg, const char *rate, libxl_device_nic *nic)
{
    uint64_t bytes_per_sec = 0;
    uint64_t bytes_per_interval = 0;
    uint32_t interval_usecs = 50000UL; /* Default to 50ms */
    char *p, *tmprate;
    int rc = 0;

    tmprate = strdup(rate);
    if (tmprate == NULL) {
        rc = ENOMEM;
        goto out;
    }

    p = strchr(tmprate, '@');
    if (p != NULL)
        *p++ = 0;

    if (!strcmp(tmprate,"")) {
        xlu__vif_err(cfg, "no rate specified", rate);
        rc = EINVAL;
        goto out;
    }

    rc = vif_parse_rate_bytes_per_sec(cfg, tmprate, &bytes_per_sec);
    if (rc) goto out;

    if (p != NULL) {
        rc = vif_parse_rate_interval_usecs(cfg, p, &interval_usecs);
        if (rc) goto out;
    }

    if (interval_usecs != 0 && (bytes_per_sec > (UINT64_MAX / interval_usecs))) {
        xlu__vif_err(cfg, "rate overflow", rate);
        rc = EOVERFLOW;
        goto out;
    }

    bytes_per_interval =
        (((uint64_t) bytes_per_sec * (uint64_t) interval_usecs) / 1000000UL);

    nic->rate_interval_usecs = interval_usecs;
    nic->rate_bytes_per_interval = bytes_per_interval;

out:
    free(tmprate);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
