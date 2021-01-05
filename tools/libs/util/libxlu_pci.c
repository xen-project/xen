#define _GNU_SOURCE

#include <ctype.h>

#include "libxlu_internal.h"
#include "libxlu_disk_l.h"
#include "libxlu_disk_i.h"
#include "libxlu_cfg_i.h"


#define XLU__PCI_ERR(_c, _x, _a...) \
    if((_c) && (_c)->report) fprintf((_c)->report, _x, ##_a)

static int parse_bdf(libxl_device_pci *pci, const char *str, const char **endp)
{
    const char *ptr = str;
    unsigned int colons = 0;
    unsigned int domain, bus, dev, func;
    int n;

    /* Count occurrences of ':' to detrmine presence/absence of the 'domain' */
    while (isxdigit(*ptr) || *ptr == ':') {
        if (*ptr == ':')
            colons++;
        ptr++;
    }

    ptr = str;
    switch (colons) {
    case 1:
        domain = 0;
        if (sscanf(ptr, "%x:%x.%n", &bus, &dev, &n) != 2)
            return ERROR_INVAL;
        break;
    case 2:
        if (sscanf(ptr, "%x:%x:%x.%n", &domain, &bus, &dev, &n) != 3)
            return ERROR_INVAL;
        break;
    default:
        return ERROR_INVAL;
    }

    if (domain > 0xffff || bus > 0xff || dev > 0x1f)
        return ERROR_INVAL;

    ptr += n;
    if (*ptr == '*') {
        pci->vfunc_mask = LIBXL_PCI_FUNC_ALL;
        func = 0;
        ptr++;
    } else {
        if (sscanf(ptr, "%x%n", &func, &n) != 1)
            return ERROR_INVAL;
        if (func > 7)
            return ERROR_INVAL;
        pci->vfunc_mask = 1;
        ptr += n;
    }

    pci->domain = domain;
    pci->bus = bus;
    pci->dev = dev;
    pci->func = func;

    if (endp)
        *endp = ptr;

    return 0;
}

static int parse_vslot(uint32_t *vdevfnp, const char *str, const char **endp)
{
    const char *ptr = str;
    unsigned int val;
    int n;

    if (sscanf(ptr, "%x%n", &val, &n) != 1)
        return ERROR_INVAL;

    if (val > 0x1f)
        return ERROR_INVAL;

    ptr += n;

    *vdevfnp = val << 3;

    if (endp)
        *endp = ptr;

    return 0;
}

static int parse_key_val(char **keyp, char**valp, const char *str,
                         const char **endp)
{
    const char *ptr = str;
    char *key, *val;

    while (*ptr != '=' && *ptr != '\0')
        ptr++;

    if (*ptr == '\0')
        return ERROR_INVAL;

    key = strndup(str, ptr - str);
    if (!key)
        return ERROR_NOMEM;

    str = ++ptr; /* skip '=' */
    while (*ptr != ',' && *ptr != '\0')
        ptr++;

    val = strndup(str, ptr - str);
    if (!val) {
        free(key);
        return ERROR_NOMEM;
    }

    if (*ptr == ',')
        ptr++;

    *keyp = key;
    *valp = val;
    *endp = ptr;

    return 0;
}

static int parse_rdm_policy(XLU_Config *cfg, libxl_rdm_reserve_policy *policy,
                            const char *str)
{
    int ret = libxl_rdm_reserve_policy_from_string(str, policy);

    if (ret)
        XLU__PCI_ERR(cfg, "Unknown RDM policy: %s", str);

    return ret;
}

int xlu_pci_parse_bdf(XLU_Config *cfg, libxl_device_pci *pci, const char *str)
{
    return parse_bdf(pci, str, NULL);
}

int xlu_pci_parse_spec_string(XLU_Config *cfg, libxl_device_pci *pci,
                              const char *str)
{
    const char *ptr = str;
    bool bdf_present = false;
    bool name_present = false;
    int ret;

    /* Attempt to parse 'bdf' as positional parameter */
    ret = parse_bdf(pci, ptr, &ptr);
    if (!ret) {
        bdf_present = true;

        /* Check whether 'vslot' if present */
        if (*ptr == '@') {
            ret = parse_vslot(&pci->vdevfn, ++ptr, &ptr);
            if (ret)
                return ret;
        }
        if (*ptr == ',')
            ptr++;
        else if (*ptr != '\0')
            return ERROR_INVAL;
    }

    /* Parse the rest as 'key=val' pairs */
    while (*ptr != '\0') {
        char *key, *val;

        ret = parse_key_val(&key, &val, ptr, &ptr);
        if (ret)
            return ret;

        if (!strcmp(key, "bdf")) {
            ret = parse_bdf(pci, val, NULL);
            if (!ret) bdf_present = true;
        } else if (!strcmp(key, "vslot")) {
            ret = parse_vslot(&pci->vdevfn, val, NULL);
        } else if (!strcmp(key, "permissive")) {
            pci->permissive = atoi(val);
        } else if (!strcmp(key, "msitranslate")) {
            pci->msitranslate = atoi(val);
        } else if (!strcmp(key, "seize")) {
            pci->seize= atoi(val);
        } else if (!strcmp(key, "power_mgmt")) {
            pci->power_mgmt = atoi(val);
        } else if (!strcmp(key, "rdm_policy")) {
            ret = parse_rdm_policy(cfg, &pci->rdm_policy, val);
        } else if (!strcmp(key, "name")) {
            name_present = true;
            pci->name = strdup(val);
            if (!pci->name) ret = ERROR_NOMEM;
        } else {
            XLU__PCI_ERR(cfg, "Unknown PCI_SPEC_STRING option: %s", key);
            ret = ERROR_INVAL;
        }

        free(key);
        free(val);

        if (ret)
            return ret;
    }

    if (!(bdf_present ^ name_present))
        return ERROR_INVAL;

    return 0;
}

int xlu_rdm_parse(XLU_Config *cfg, libxl_rdm_reserve *rdm, const char *str)
{
#define STATE_TYPE           0
#define STATE_RDM_STRATEGY   1
#define STATE_RESERVE_POLICY 2
#define STATE_TERMINAL       3

    unsigned state = STATE_TYPE;
    char *buf2, *tok, *ptr, *end;

    if (NULL == (buf2 = ptr = strdup(str)))
        return ERROR_NOMEM;

    for (tok = ptr, end = ptr + strlen(ptr) + 1; ptr < end; ptr++) {
        switch(state) {
        case STATE_TYPE:
            if (*ptr == '=') {
                *ptr = '\0';
                if (!strcmp(tok, "strategy")) {
                    state = STATE_RDM_STRATEGY;
                } else if (!strcmp(tok, "policy")) {
                    state = STATE_RESERVE_POLICY;
                } else {
                    XLU__PCI_ERR(cfg, "Unknown RDM state option: %s", tok);
                    goto parse_error;
                }
                tok = ptr + 1;
            }
            break;
        case STATE_RDM_STRATEGY:
            if (*ptr == '\0' || *ptr == ',') {
                state = *ptr == ',' ? STATE_TYPE : STATE_TERMINAL;
                *ptr = '\0';
                if (!strcmp(tok, "host")) {
                    rdm->strategy = LIBXL_RDM_RESERVE_STRATEGY_HOST;
                } else {
                    XLU__PCI_ERR(cfg, "Unknown RDM strategy option: %s", tok);
                    goto parse_error;
                }
                tok = ptr + 1;
            }
            break;
        case STATE_RESERVE_POLICY:
            if (*ptr == ',' || *ptr == '\0') {
                state = *ptr == ',' ? STATE_TYPE : STATE_TERMINAL;
                *ptr = '\0';
                if (!parse_rdm_policy(cfg, &rdm->policy, tok))
                    goto parse_error;
                tok = ptr + 1;
            }
        default:
            break;
        }
    }

    if (tok != ptr || state != STATE_TERMINAL)
        goto parse_error;

    free(buf2);

    return 0;

parse_error:
    free(buf2);
    return ERROR_INVAL;

#undef STATE_TYPE
#undef STATE_RDM_STRATEGY
#undef STATE_RESERVE_POLICY
#undef STATE_TERMINAL
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
