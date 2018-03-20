#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxlu_internal.h"
#include "xenctrl.h"

#include <ctype.h>

#define PARAM_RE(EXPR) "^\\s*" EXPR "\\s*(,|$)"
#define WORD_RE         "([_a-zA-Z0-9]+)"
#define EQU_RE         PARAM_RE(WORD_RE "\\s*=\\s*" WORD_RE)

#define RET_INVAL(msg, curr_str)  do {              \
        xlu__sshm_err(cfg, msg, curr_str);          \
        rc = EINVAL;                                \
        goto out;                                   \
    } while(0)

/* set a member in libxl_static_shm and report an error if it's respecified,
 * @curr_str indicates the head of the remaining string. */
#define SET_VAL(var, name, type, value, curr_str)  do {                 \
        if ((var) != LIBXL_SSHM_##type##_UNKNOWN && (var) != value) {   \
            RET_INVAL("\"" name "\" respecified", curr_str);            \
        }                                                               \
        (var) = value;                                                  \
    } while(0)


static void xlu__sshm_err(XLU_Config *cfg, const char *msg,
                          const char *curr_str) {
    fprintf(cfg->report,
            "%s: config parsing error in shared_memory: %s at '%s'\n",
            cfg->config_source, msg, curr_str);
}

static int parse_prot(XLU_Config *cfg, char *str, libxl_sshm_prot *prot)
{
    int rc;
    libxl_sshm_prot new_prot;

    if (!strcmp(str, "rw")) {
        new_prot = LIBXL_SSHM_PROT_RW;
    } else {
        RET_INVAL("invalid permission flags", str);
    }

    SET_VAL(*prot, "permission flags", PROT, new_prot, str);

    rc = 0;

 out:
    return rc;
}

static int parse_cachepolicy(XLU_Config *cfg, char *str,
                             libxl_sshm_cachepolicy *policy)
{
    int rc;
    libxl_sshm_cachepolicy new_policy;

    if (!strcmp(str, "ARM_normal")) {
        new_policy = LIBXL_SSHM_CACHEPOLICY_ARM_NORMAL;
    } else if (!strcmp(str, "x86_normal")) {
        new_policy = LIBXL_SSHM_CACHEPOLICY_X86_NORMAL;
    } else {
        RET_INVAL("invalid cache policy", str);
    }

    SET_VAL(*policy, "cache policy", CACHEPOLICY, new_policy, str);
    rc = 0;

 out:
    return rc;
}

/* handle key = value pairs */
static int handle_equ(XLU_Config *cfg, char *key, char *val,
                      libxl_static_shm *sshm)
{
    int rc;

    if (!strcmp(key, "id")) {
        if (strlen(val) > LIBXL_SSHM_ID_MAXLEN) { RET_INVAL("id too long", val); }
        if (sshm->id && !strcmp(sshm->id, val)) {
            RET_INVAL("id respecified", val);
        }

        sshm->id = strdup(val);
        if (!sshm->id) {
            fprintf(stderr, "sshm parser out of memory\n");
            rc = ENOMEM;
            goto out;
        }
    } else if (!strcmp(key, "role")) {
        libxl_sshm_role new_role;

        if (!strcmp("master", val)) {
            new_role = LIBXL_SSHM_ROLE_MASTER;
        } else if (!strcmp("slave", val)) {
            new_role = LIBXL_SSHM_ROLE_SLAVE;
        } else {
            RET_INVAL("invalid role", val);
        }

        SET_VAL(sshm->role, "role", ROLE, new_role, val);
    } else if (!strcmp(key, "begin") ||
               !strcmp(key, "end") ||
               !strcmp(key, "offset")) {
        char *endptr;
        int base = 10;
        uint64_t new_addr;

        /* Could be in hex form. Note that we don't need to check the length here,
         * for val[] is NULL-terminated */
        if (val[0] == '0' && val[1] == 'x') { base = 16; }
        new_addr = strtoull(val, &endptr, base);
        if (errno == ERANGE || *endptr)
            RET_INVAL("invalid begin/end/offset", val);
        if (new_addr & ~XC_PAGE_MASK)
            RET_INVAL("begin/end/offset is not a multiple of 4K", val);

        /* begin or end */
        if (key[0] == 'b') {
            SET_VAL(sshm->begin, "beginning address", RANGE, new_addr, val);
        } else if(key[0] == 'e'){
            SET_VAL(sshm->end, "ending address", RANGE, new_addr, val);
        } else {
            SET_VAL(sshm->offset, "offset", RANGE, new_addr, val);
        }
    } else if (!strcmp(key, "prot")) {
        rc = parse_prot(cfg, val, &sshm->prot);
        if (rc) { goto out; }
    } else if (!strcmp(key, "cache_policy")) {
        rc = parse_cachepolicy(cfg, val, &sshm->cache_policy);
        if (rc) { goto out; }
    } else {
        RET_INVAL("invalid option", key);
    }

    rc = 0;

 out:
    return rc;
}

int xlu_sshm_parse(XLU_Config *cfg, const char *spec,
                   libxl_static_shm *sshm)
{
    int rc;
    regex_t equ_rec;
    char *buf2 = NULL, *ptr = NULL;
    regmatch_t pmatch[3];

    rc = regcomp(&equ_rec, EQU_RE, REG_EXTENDED);
    if (rc) {
        fprintf(stderr, "sshm parser failed to initialize\n");
        goto out;
    }

    buf2 = ptr = strdup(spec);
    if (!buf2) {
        fprintf(stderr, "sshm parser out of memory\n");
        rc = ENOMEM;
        goto out;
    }

    /* main parsing loop */
    while (true) {
        if (!*ptr) { break; }
        if (regexec(&equ_rec, ptr, 3, pmatch, 0))
            RET_INVAL("unrecognized token", ptr);

        ptr[pmatch[1].rm_eo] = '\0';
        ptr[pmatch[2].rm_eo] = '\0';
        rc = handle_equ(cfg, ptr + pmatch[1].rm_so,
                        ptr + pmatch[2].rm_so, sshm);
        if (rc) { goto out; }

        ptr += pmatch[0].rm_eo;
    }

    if (*ptr) { RET_INVAL("invalid syntax", ptr); }

    /* do some early checks */
    if (!sshm->id) {
        RET_INVAL("id not specified", spec);
    }
    if (sshm->begin == LIBXL_SSHM_RANGE_UNKNOWN) {
        RET_INVAL("begin address not specified", spec);
    }
    if (sshm->end == LIBXL_SSHM_RANGE_UNKNOWN) {
        RET_INVAL("end address not specified", spec);
    }
    if (sshm->begin > sshm->end) {
        RET_INVAL("begin address larger that end address", spec);
    }

    rc = 0;

 out:
    if (buf2) { free(buf2); }
    regfree(&equ_rec);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
