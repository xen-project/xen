#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxlu_internal.h"
#include "libxlu_disk_l.h"
#include "libxlu_disk_i.h"
#include "libxlu_cfg_i.h"


#define XLU__PCI_ERR(_c, _x, _a...) \
    if((_c) && (_c)->report) fprintf((_c)->report, _x, ##_a)

static int hex_convert(const char *str, unsigned int *val, unsigned int mask)
{
    unsigned long ret;
    char *end;

    ret = strtoul(str, &end, 16);
    if ( end == str || *end != '\0' )
        return -1;
    if ( ret & ~mask )
        return -1;
    *val = (unsigned int)ret & mask;
    return 0;
}

static int pcidev_struct_fill(libxl_device_pci *pcidev, unsigned int domain,
                               unsigned int bus, unsigned int dev,
                               unsigned int func, unsigned int vdevfn)
{
    pcidev->domain = domain;
    pcidev->bus = bus;
    pcidev->dev = dev;
    pcidev->func = func;
    pcidev->vdevfn = vdevfn;
    return 0;
}

#define STATE_DOMAIN    0
#define STATE_BUS       1
#define STATE_DEV       2
#define STATE_FUNC      3
#define STATE_VSLOT     4
#define STATE_OPTIONS_K 6
#define STATE_OPTIONS_V 7
#define STATE_TERMINAL  8
#define STATE_TYPE      9
#define STATE_RDM_STRATEGY      10
#define STATE_RESERVE_POLICY    11
int xlu_pci_parse_bdf(XLU_Config *cfg, libxl_device_pci *pcidev, const char *str)
{
    unsigned state = STATE_DOMAIN;
    unsigned dom, bus, dev, func, vslot = 0;
    char *buf2, *tok, *ptr, *end, *optkey = NULL;

    if ( NULL == (buf2 = ptr = strdup(str)) )
        return ERROR_NOMEM;

    for(tok = ptr, end = ptr + strlen(ptr) + 1; ptr < end; ptr++) {
        switch(state) {
        case STATE_DOMAIN:
            if ( *ptr == ':' ) {
                state = STATE_BUS;
                *ptr = '\0';
                if ( hex_convert(tok, &dom, 0xffff) )
                    goto parse_error;
                tok = ptr + 1;
            }
            break;
        case STATE_BUS:
            if ( *ptr == ':' ) {
                state = STATE_DEV;
                *ptr = '\0';
                if ( hex_convert(tok, &bus, 0xff) )
                    goto parse_error;
                tok = ptr + 1;
            }else if ( *ptr == '.' ) {
                state = STATE_FUNC;
                *ptr = '\0';
                if ( dom & ~0xff )
                    goto parse_error;
                bus = dom;
                dom = 0;
                if ( hex_convert(tok, &dev, 0xff) )
                    goto parse_error;
                tok = ptr + 1;
            }
            break;
        case STATE_DEV:
            if ( *ptr == '.' ) {
                state = STATE_FUNC;
                *ptr = '\0';
                if ( hex_convert(tok, &dev, 0xff) )
                    goto parse_error;
                tok = ptr + 1;
            }
            break;
        case STATE_FUNC:
            if ( *ptr == '\0' || *ptr == '@' || *ptr == ',' ) {
                switch( *ptr ) {
                case '\0':
                    state = STATE_TERMINAL;
                    break;
                case '@':
                    state = STATE_VSLOT;
                    break;
                case ',':
                    state = STATE_OPTIONS_K;
                    break;
                }
                *ptr = '\0';
                if ( !strcmp(tok, "*") ) {
                    pcidev->vfunc_mask = LIBXL_PCI_FUNC_ALL;
                }else{
                    if ( hex_convert(tok, &func, 0x7) )
                        goto parse_error;
                    pcidev->vfunc_mask = (1 << 0);
                }
                tok = ptr + 1;
            }
            break;
        case STATE_VSLOT:
            if ( *ptr == '\0' || *ptr == ',' ) {
                state = ( *ptr == ',' ) ? STATE_OPTIONS_K : STATE_TERMINAL;
                *ptr = '\0';
                if ( hex_convert(tok, &vslot, 0xff) )
                    goto parse_error;
                tok = ptr + 1;
            }
            break;
        case STATE_OPTIONS_K:
            if ( *ptr == '=' ) {
                state = STATE_OPTIONS_V;
                *ptr = '\0';
                optkey = tok;
                tok = ptr + 1;
            }
            break;
        case STATE_OPTIONS_V:
            if ( *ptr == ',' || *ptr == '\0' ) {
                state = (*ptr == ',') ? STATE_OPTIONS_K : STATE_TERMINAL;
                *ptr = '\0';
                if ( !strcmp(optkey, "msitranslate") ) {
                    pcidev->msitranslate = atoi(tok);
                }else if ( !strcmp(optkey, "power_mgmt") ) {
                    pcidev->power_mgmt = atoi(tok);
                }else if ( !strcmp(optkey, "permissive") ) {
                    pcidev->permissive = atoi(tok);
                }else if ( !strcmp(optkey, "seize") ) {
                    pcidev->seize = atoi(tok);
                } else if (!strcmp(optkey, "rdm_policy")) {
                    if (!strcmp(tok, "strict")) {
                        pcidev->rdm_policy = LIBXL_RDM_RESERVE_POLICY_STRICT;
                    } else if (!strcmp(tok, "relaxed")) {
                        pcidev->rdm_policy = LIBXL_RDM_RESERVE_POLICY_RELAXED;
                    } else {
                        XLU__PCI_ERR(cfg, "%s is not an valid PCI RDM property"
                                          " policy: 'strict' or 'relaxed'.",
                                     tok);
                        goto parse_error;
                    }
                } else {
                    XLU__PCI_ERR(cfg, "Unknown PCI BDF option: %s", optkey);
                }
                tok = ptr + 1;
            }
        default:
            break;
        }
    }

    if ( tok != ptr || state != STATE_TERMINAL )
        goto parse_error;

    /* Just a pretty way to fill in the values */
    pcidev_struct_fill(pcidev, dom, bus, dev, func, vslot << 3);

    free(buf2);

    return 0;

parse_error:
    free(buf2);
    return ERROR_INVAL;
}

int xlu_rdm_parse(XLU_Config *cfg, libxl_rdm_reserve *rdm, const char *str)
{
    unsigned state = STATE_TYPE;
    char *buf2, *tok, *ptr, *end;

    if (NULL == (buf2 = ptr = strdup(str)))
        return ERROR_NOMEM;

    for (tok = ptr, end = ptr + strlen(ptr) + 1; ptr < end; ptr++) {
        switch(state) {
        case STATE_TYPE:
            if (*ptr == '=') {
                state = STATE_RDM_STRATEGY;
                *ptr = '\0';
                if (strcmp(tok, "strategy")) {
                    XLU__PCI_ERR(cfg, "Unknown RDM state option: %s", tok);
                    goto parse_error;
                }
                tok = ptr + 1;
            }
            break;
        case STATE_RDM_STRATEGY:
            if (*ptr == '\0' || *ptr == ',') {
                state = STATE_RESERVE_POLICY;
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
            if (*ptr == '=') {
                state = STATE_OPTIONS_V;
                *ptr = '\0';
                if (strcmp(tok, "policy")) {
                    XLU__PCI_ERR(cfg, "Unknown RDM property value: %s", tok);
                    goto parse_error;
                }
                tok = ptr + 1;
            }
            break;
        case STATE_OPTIONS_V:
            if (*ptr == ',' || *ptr == '\0') {
                state = STATE_TERMINAL;
                *ptr = '\0';
                if (!strcmp(tok, "strict")) {
                    rdm->policy = LIBXL_RDM_RESERVE_POLICY_STRICT;
                } else if (!strcmp(tok, "relaxed")) {
                    rdm->policy = LIBXL_RDM_RESERVE_POLICY_RELAXED;
                } else {
                    XLU__PCI_ERR(cfg, "Unknown RDM property policy value: %s",
                                 tok);
                    goto parse_error;
                }
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
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
