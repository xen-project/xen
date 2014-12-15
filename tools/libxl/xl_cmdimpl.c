/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/utsname.h> /* for utsname in xl info */
#include <xentoollog.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <xen/hvm/e820.h>

#include "libxl.h"
#include "libxl_utils.h"
#include "libxl_json.h"
#include "libxlutil.h"
#include "xl.h"

/* For calls which return an errno on failure */
#define CHK_ERRNOVAL( call ) ({                                         \
        int chk_errnoval = (call);                                      \
        if (chk_errnoval < 0)                                           \
            abort();                                                    \
        else if (chk_errnoval > 0) {                                    \
            fprintf(stderr,"xl: fatal error: %s:%d: %s: %s\n",          \
                    __FILE__,__LINE__, strerror(chk_errnoval), #call);  \
            exit(-ERROR_FAIL);                                          \
        }                                                               \
    })

/* For calls which return -1 and set errno on failure */
#define CHK_SYSCALL( call ) ({                                          \
        if ((call) == -1) {                                             \
            fprintf(stderr,"xl: fatal error: %s:%d: %s: %s\n",          \
                    __FILE__,__LINE__, strerror(errno), #call);         \
            exit(-ERROR_FAIL);                                          \
        }                                                               \
    })

#define MUST( call ) ({                                                 \
        int must_rc = (call);                                           \
        if (must_rc < 0) {                                                  \
            fprintf(stderr,"xl: fatal error: %s:%d, rc=%d: %s\n",       \
                    __FILE__,__LINE__, must_rc, #call);                 \
            exit(-must_rc);                                             \
        }                                                               \
    })

#define STR_HAS_PREFIX( a, b )  \
    ( strncmp(a, b, strlen(b)) == 0 )
#define STR_SKIP_PREFIX( a, b ) \
    ( STR_HAS_PREFIX(a, b) ? ((a) += strlen(b), 1) : 0 )


int logfile = 2;

/* every libxl action in xl uses this same libxl context */
libxl_ctx *ctx;

xlchild children[child_max];

#define INVALID_DOMID ~0
static const char *common_domname;
static int fd_lock = -1;

static const char savefileheader_magic[32]=
    "Xen saved domain, xl format\n \0 \r";

static const char migrate_receiver_banner[]=
    "xl migration receiver ready, send binary domain data.\n";
static const char migrate_receiver_ready[]=
    "domain received, ready to unpause";
static const char migrate_permission_to_go[]=
    "domain is yours, you are cleared to unpause";
static const char migrate_report[]=
    "my copy unpause results are as follows";
  /* followed by one byte:
   *     0: everything went well, domain is running
   *            next thing is we all exit
   * non-0: things went badly
   *            next thing should be a migrate_permission_to_go
   *            from target to source
   */

#define XL_MANDATORY_FLAG_JSON (1U << 0) /* config data is in JSON format */
#define XL_MANDATORY_FLAG_ALL  (XL_MANDATORY_FLAG_JSON)
struct save_file_header {
    char magic[32]; /* savefileheader_magic */
    /* All uint32_ts are in domain's byte order. */
    uint32_t byteorder; /* SAVEFILE_BYTEORDER_VALUE */
    uint32_t mandatory_flags; /* unknown flags => reject restore */
    uint32_t optional_flags; /* unknown flags => reject restore */
    uint32_t optional_data_len; /* skip, or skip tail, if not understood */
};


static const char *action_on_shutdown_names[] = {
    [LIBXL_ACTION_ON_SHUTDOWN_DESTROY] = "destroy",

    [LIBXL_ACTION_ON_SHUTDOWN_RESTART] = "restart",
    [LIBXL_ACTION_ON_SHUTDOWN_RESTART_RENAME] = "rename-restart",

    [LIBXL_ACTION_ON_SHUTDOWN_PRESERVE] = "preserve",

    [LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_DESTROY] = "coredump-destroy",
    [LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_RESTART] = "coredump-restart",
};

/* Optional data, in order:
 *   4 bytes uint32_t  config file size
 *   n bytes           config file in Unix text file format
 */

#define SAVEFILE_BYTEORDER_VALUE ((uint32_t)0x01020304UL)

struct domain_create {
    int debug;
    int daemonize;
    int monitor; /* handle guest reboots etc */
    int paused;
    int dryrun;
    int quiet;
    int vnc;
    int vncautopass;
    int console_autoconnect;
    int checkpointed_stream;
    const char *config_file;
    const char *extra_config; /* extra config string */
    const char *restore_file;
    int migrate_fd; /* -1 means none */
    char **migration_domname_r; /* from malloc */
};


static uint32_t find_domain(const char *p) __attribute__((warn_unused_result));
static uint32_t find_domain(const char *p)
{
    uint32_t domid;
    int rc;

    rc = libxl_domain_qualifier_to_domid(ctx, p, &domid);
    if (rc) {
        fprintf(stderr, "%s is an invalid domain identifier (rc=%d)\n", p, rc);
        exit(2);
    }
    common_domname = libxl_domid_to_name(ctx, domid);
    return domid;
}

int child_report(xlchildnum child)
{
    int status;
    pid_t got = xl_waitpid(child, &status, 0);
    if (got < 0) {
        fprintf(stderr, "xl: warning, failed to waitpid for %s: %s\n",
                children[child].description, strerror(errno));
        return ERROR_FAIL;
    } else if (status) {
        xl_report_child_exitstatus(XTL_ERROR, child, got, status);
        return ERROR_FAIL;
    } else {
        return 0;
    }
}

static void console_child_report(xlchildnum child)
{
    if (xl_child_pid(child))
        child_report(child);
}

static int vncviewer(uint32_t domid, int autopass)
{
    libxl_vncviewer_exec(ctx, domid, autopass);
    fprintf(stderr, "Unable to execute vncviewer\n");
    return 1;
}

static void autoconnect_vncviewer(uint32_t domid, int autopass)
{
   console_child_report(child_vncviewer);

    pid_t pid = xl_fork(child_vncviewer, "vncviewer child");
    if (pid)
        return;

    postfork();

    sleep(1);
    vncviewer(domid, autopass);
    _exit(1);
}

static int acquire_lock(void)
{
    int rc;
    struct flock fl;

    /* lock already acquired */
    if (fd_lock >= 0)
        return ERROR_INVAL;

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fd_lock = open(lockfile, O_WRONLY|O_CREAT, S_IWUSR);
    if (fd_lock < 0) {
        fprintf(stderr, "cannot open the lockfile %s errno=%d\n", lockfile, errno);
        return ERROR_FAIL;
    }
    if (fcntl(fd_lock, F_SETFD, FD_CLOEXEC) < 0) {
        close(fd_lock);
        fprintf(stderr, "cannot set cloexec to lockfile %s errno=%d\n", lockfile, errno);
        return ERROR_FAIL;
    }
get_lock:
    rc = fcntl(fd_lock, F_SETLKW, &fl);
    if (rc < 0 && errno == EINTR)
        goto get_lock;
    if (rc < 0) {
        fprintf(stderr, "cannot acquire lock %s errno=%d\n", lockfile, errno);
        rc = ERROR_FAIL;
    } else
        rc = 0;
    return rc;
}

static int release_lock(void)
{
    int rc;
    struct flock fl;

    /* lock not acquired */
    if (fd_lock < 0)
        return ERROR_INVAL;

release_lock:
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    rc = fcntl(fd_lock, F_SETLKW, &fl);
    if (rc < 0 && errno == EINTR)
        goto release_lock;
    if (rc < 0) {
        fprintf(stderr, "cannot release lock %s, errno=%d\n", lockfile, errno);
        rc = ERROR_FAIL;
    } else
        rc = 0;
    close(fd_lock);
    fd_lock = -1;

    return rc;
}

static void *xmalloc(size_t sz) {
    void *r;
    r = malloc(sz);
    if (!r) { fprintf(stderr,"xl: Unable to malloc %lu bytes.\n",
                      (unsigned long)sz); exit(-ERROR_FAIL); }
    return r;
}

static void *xrealloc(void *ptr, size_t sz) {
    void *r;
    if (!sz) { free(ptr); return 0; }
      /* realloc(non-0, 0) has a useless return value;
       * but xrealloc(anything, 0) is like free
       */
    r = realloc(ptr, sz);
    if (!r) { fprintf(stderr,"xl: Unable to realloc to %lu bytes.\n",
                      (unsigned long)sz); exit(-ERROR_FAIL); }
    return r;
}

static char *xstrdup(const char *x)
{
    char *r;
    r = strdup(x);
    if (!r) {
        fprintf(stderr, "xl: Unable to strdup a string of length %zu.\n",
                strlen(x));
        exit(-ERROR_FAIL);
    }
    return r;
}

#define ARRAY_EXTEND_INIT(array,count,initfn)                           \
    ({                                                                  \
        typeof((count)) array_extend_old_count = (count);               \
        (count)++;                                                      \
        (array) = xrealloc((array), sizeof(*array) * (count));          \
        (initfn)(&(array)[array_extend_old_count]);                     \
        (array)[array_extend_old_count].devid = array_extend_old_count; \
        &(array)[array_extend_old_count];                               \
    })

#define LOG(_f, _a...)   dolog(__FILE__, __LINE__, __func__, _f "\n", ##_a)

static void dolog(const char *file, int line, const char *func, char *fmt, ...)
     __attribute__((format(printf,4,5)));

static void dolog(const char *file, int line, const char *func, char *fmt, ...)
{
    va_list ap;
    char *s = NULL;
    int rc;

    va_start(ap, fmt);
    rc = vasprintf(&s, fmt, ap);
    va_end(ap);
    if (rc >= 0)
        /* we ignore write errors since we have no way to report them;
         * the alternative would be to abort the whole program */
        libxl_write_exactly(NULL, logfile, s, rc, NULL, NULL);
    free(s);
}

static yajl_gen_status printf_info_one_json(yajl_gen hand, int domid,
                                            libxl_domain_config *d_config)
{
    yajl_gen_status s;

    s = yajl_gen_map_open(hand);
    if (s != yajl_gen_status_ok)
        goto out;

    s = yajl_gen_string(hand, (const unsigned char *)"domid",
                        sizeof("domid")-1);
    if (s != yajl_gen_status_ok)
        goto out;
    if (domid != -1)
        s = yajl_gen_integer(hand, domid);
    else
        s = yajl_gen_null(hand);
    if (s != yajl_gen_status_ok)
        goto out;

    s = yajl_gen_string(hand, (const unsigned char *)"config",
                        sizeof("config")-1);
    if (s != yajl_gen_status_ok)
        goto out;
    s = libxl_domain_config_gen_json(hand, d_config);
    if (s != yajl_gen_status_ok)
        goto out;

    s = yajl_gen_map_close(hand);
    if (s != yajl_gen_status_ok)
        goto out;

out:
    return s;
}
static void printf_info(enum output_format output_format,
                        int domid,
                        libxl_domain_config *d_config, FILE *fh)
{
    if (output_format == OUTPUT_FORMAT_SXP)
        return printf_info_sexp(domid, d_config, fh);

    const char *buf;
    libxl_yajl_length len = 0;
    yajl_gen_status s;
    yajl_gen hand;

    hand = libxl_yajl_gen_alloc(NULL);
    if (!hand) {
        fprintf(stderr, "unable to allocate JSON generator\n");
        return;
    }

    s = printf_info_one_json(hand, domid, d_config);
    if (s != yajl_gen_status_ok)
        goto out;

    s = yajl_gen_get_buf(hand, (const unsigned char **)&buf, &len);
    if (s != yajl_gen_status_ok)
        goto out;

    fputs(buf, fh);

out:
    yajl_gen_free(hand);

    if (s != yajl_gen_status_ok)
        fprintf(stderr,
                "unable to format domain config as JSON (YAJL:%d)\n", s);

    if (ferror(fh) || fflush(fh)) {
        if (fh == stdout)
            perror("stdout");
        else
            perror("stderr");
        exit(-1);
    }
}

static int do_daemonize(char *name)
{
    char *fullname;
    pid_t child1;
    int nullfd, ret = 0;

    child1 = xl_fork(child_waitdaemon, "domain monitoring daemonizing child");
    if (child1) {
        ret = child_report(child_waitdaemon);
        if (ret) goto out;
        ret = 1;
        goto out;
    }

    postfork();

    ret = libxl_create_logfile(ctx, name, &fullname);
    if (ret) {
        LOG("failed to open logfile %s: %s",fullname,strerror(errno));
        exit(-1);
    }

    CHK_SYSCALL(logfile = open(fullname, O_WRONLY|O_CREAT|O_APPEND, 0644));
    free(fullname);

    CHK_SYSCALL(nullfd = open("/dev/null", O_RDONLY));
    dup2(nullfd, 0);
    dup2(logfile, 1);
    dup2(logfile, 2);

    CHK_SYSCALL(daemon(0, 1));

out:
    return ret;
}

static int parse_action_on_shutdown(const char *buf, libxl_action_on_shutdown *a)
{
    int i;
    const char *n;

    for (i = 0; i < sizeof(action_on_shutdown_names) / sizeof(action_on_shutdown_names[0]); i++) {
        n = action_on_shutdown_names[i];

        if (!n) continue;

        if (strcmp(buf, n) == 0) {
            *a = i;
            return 1;
        }
    }
    return 0;
}

#define DSTATE_INITIAL   0
#define DSTATE_TAP       1
#define DSTATE_PHYSPATH  2
#define DSTATE_VIRTPATH  3
#define DSTATE_VIRTTYPE  4
#define DSTATE_RW        5
#define DSTATE_TERMINAL  6

static void parse_disk_config_multistring(XLU_Config **config,
                                          int nspecs, const char *const *specs,
                                          libxl_device_disk *disk)
{
    int e;

    libxl_device_disk_init(disk);

    if (!*config) {
        *config = xlu_cfg_init(stderr, "command line");
        if (!*config) { perror("xlu_cfg_init"); exit(-1); }
    }

    e = xlu_disk_parse(*config, nspecs, specs, disk);
    if (e == EINVAL) exit(-1);
    if (e) {
        fprintf(stderr,"xlu_disk_parse failed: %s\n",strerror(errno));
        exit(-1);
    }
}

static void parse_disk_config(XLU_Config **config, const char *spec,
                              libxl_device_disk *disk)
{
    parse_disk_config_multistring(config, 1, &spec, disk);
}

static void parse_vif_rate(XLU_Config **config, const char *rate,
                           libxl_device_nic *nic)
{
    int e;

    e = xlu_vif_parse_rate(*config, rate, nic);
    if (e == EINVAL || e == EOVERFLOW) exit(-1);
    if (e) {
        fprintf(stderr,"xlu_vif_parse_rate failed: %s\n",strerror(errno));
        exit(-1);
    }
}

static void set_default_nic_values(libxl_device_nic *nic)
{

    if (default_vifscript) {
        free(nic->script);
        nic->script = strdup(default_vifscript);
    }

    if (default_bridge) {
        free(nic->bridge);
        nic->bridge = strdup(default_bridge);
    }

    if (default_gatewaydev) {
        free(nic->gatewaydev);
        nic->gatewaydev = strdup(default_gatewaydev);
    }

    if (default_vifbackend) {
        free(nic->backend_domname);
        nic->backend_domname = strdup(default_vifbackend);
    }
}

static void split_string_into_string_list(const char *str,
                                          const char *delim,
                                          libxl_string_list *psl)
{
    char *s, *saveptr;
    const char *p;
    libxl_string_list sl;

    int i = 0, nr = 0;

    s = strdup(str);
    if (s == NULL) {
        fprintf(stderr, "unable to allocate memory to split string\n");
        exit(-1);
    }

    /* Count number of entries */
    p = strtok_r(s, delim, &saveptr);
    do {
        nr++;
    } while ((p = strtok_r(NULL, delim, &saveptr)));

    free(s);

    s = strdup(str);

    sl = malloc((nr+1) * sizeof (char *));
    if (sl == NULL) {
        fprintf(stderr, "unable to allocate memory to split string\n");
        exit(-1);
    }

    p = strtok_r(s, delim, &saveptr);
    do {
        assert(i < nr);
        sl[i] = strdup(p);
        i++;
    } while ((p = strtok_r(NULL, delim, &saveptr)));
    sl[i] = NULL;

    *psl = sl;

    free(s);
}

/* NB: this follows the interface used by <ctype.h>. See 'man 3 ctype'
   and look for CTYPE in libxl_internal.h */
typedef int (*char_predicate_t)(const int c);

static void trim(char_predicate_t predicate, const char *input, char **output)
{
    char *p, *q, *tmp;

    *output = NULL;
    if (*input == '\000')
        return;
    /* Input has length >= 1 */

    p = tmp = xstrdup(input);
    /* Skip past the characters for which predicate is true */
    while ((*p != '\000') && (predicate((unsigned char)*p)))
        p ++;
    q = p + strlen(p) - 1;
    /* q points to the last non-NULL character */
    while ((q > p) && (predicate((unsigned char)*q)))
        q --;
    /* q points to the last character we want */
    q ++;
    *q = '\000';
    *output = xstrdup(p);
    free(tmp);
}

static int split_string_into_pair(const char *str,
                                  const char *delim,
                                  char **a,
                                  char **b)
{
    char *s, *p, *saveptr, *aa = NULL, *bb = NULL;
    int rc = 0;

    s = xstrdup(str);

    p = strtok_r(s, delim, &saveptr);
    if (p == NULL) {
        rc = ERROR_INVAL;
        goto out;
    }
    aa = xstrdup(p);
    p = strtok_r(NULL, delim, &saveptr);
    if (p == NULL) {
        rc = ERROR_INVAL;
        goto out;
    }
    bb = xstrdup(p);

    *a = aa;
    aa = NULL;
    *b = bb;
    bb = NULL;
out:
    free(s);
    free(aa);
    free(bb);
    return rc;
}

static int parse_range(const char *str, unsigned long *a, unsigned long *b)
{
    const char *nstr;
    char *endptr;

    *a = *b = strtoul(str, &endptr, 10);
    if (endptr == str || *a == ULONG_MAX)
        return ERROR_INVAL;

    if (*endptr == '-') {
        nstr = endptr + 1;

        *b = strtoul(nstr, &endptr, 10);
        if (endptr == nstr || *b == ULONG_MAX || *b < *a)
            return ERROR_INVAL;
    }

    /* Valid value or range so far, but we also don't want junk after that */
    if (*endptr != '\0')
        return ERROR_INVAL;

    return 0;
}

/*
 * Add or removes a specific set of cpus (specified in str, either as
 * single cpus or as entire NUMA nodes) to/from cpumap.
 */
static int update_cpumap_range(const char *str, libxl_bitmap *cpumap)
{
    unsigned long ida, idb;
    libxl_bitmap node_cpumap;
    bool is_not = false, is_nodes = false;
    int rc = 0;

    libxl_bitmap_init(&node_cpumap);

    rc = libxl_node_bitmap_alloc(ctx, &node_cpumap, 0);
    if (rc) {
        fprintf(stderr, "libxl_node_bitmap_alloc failed.\n");
        goto out;
    }

    /* Are we adding or removing cpus/nodes? */
    if (STR_SKIP_PREFIX(str, "^")) {
        is_not = true;
    }

    /* Are we dealing with cpus or full nodes? */
    if (STR_SKIP_PREFIX(str, "node:") || STR_SKIP_PREFIX(str, "nodes:")) {
        is_nodes = true;
    }

    if (strcmp(str, "all") == 0) {
        /* We do not accept "^all" or "^nodes:all" */
        if (is_not) {
            fprintf(stderr, "Can't combine \"^\" and \"all\".\n");
            rc = ERROR_INVAL;
        } else
            libxl_bitmap_set_any(cpumap);
        goto out;
    }

    rc = parse_range(str, &ida, &idb);
    if (rc) {
        fprintf(stderr, "Invalid pcpu range: %s.\n", str);
        goto out;
    }

    /* Add or remove the specified cpus in the range */
    while (ida <= idb) {
        if (is_nodes) {
            /* Add/Remove all the cpus of a NUMA node */
            int i;

            rc = libxl_node_to_cpumap(ctx, ida, &node_cpumap);
            if (rc) {
                fprintf(stderr, "libxl_node_to_cpumap failed.\n");
                goto out;
            }

            /* Add/Remove all the cpus in the node cpumap */
            libxl_for_each_set_bit(i, node_cpumap) {
                is_not ? libxl_bitmap_reset(cpumap, i) :
                         libxl_bitmap_set(cpumap, i);
            }
        } else {
            /* Add/Remove this cpu */
            is_not ? libxl_bitmap_reset(cpumap, ida) :
                     libxl_bitmap_set(cpumap, ida);
        }
        ida++;
    }

 out:
    libxl_bitmap_dispose(&node_cpumap);
    return rc;
}

/*
 * Takes a string representing a set of cpus (specified either as
 * single cpus or as eintire NUMA nodes) and turns it into the
 * corresponding libxl_bitmap (in cpumap).
 */
static int vcpupin_parse(const char *cpu, libxl_bitmap *cpumap)
{
    char *ptr, *saveptr = NULL, *buf = strdup(cpu);
    int rc = 0;

    for (ptr = strtok_r(buf, ",", &saveptr); ptr;
         ptr = strtok_r(NULL, ",", &saveptr)) {
        rc = update_cpumap_range(ptr, cpumap);
        if (rc)
            break;
    }
    free(buf);

    return rc;
}

static void parse_top_level_vnc_options(XLU_Config *config,
                                        libxl_vnc_info *vnc)
{
    long l;

    xlu_cfg_get_defbool(config, "vnc", &vnc->enable, 0);
    xlu_cfg_replace_string (config, "vnclisten", &vnc->listen, 0);
    xlu_cfg_replace_string (config, "vncpasswd", &vnc->passwd, 0);
    if (!xlu_cfg_get_long (config, "vncdisplay", &l, 0))
        vnc->display = l;
    xlu_cfg_get_defbool(config, "vncunused", &vnc->findunused, 0);
}

static void parse_top_level_sdl_options(XLU_Config *config,
                                        libxl_sdl_info *sdl)
{
    xlu_cfg_get_defbool(config, "sdl", &sdl->enable, 0);
    xlu_cfg_get_defbool(config, "opengl", &sdl->opengl, 0);
    xlu_cfg_replace_string (config, "display", &sdl->display, 0);
    xlu_cfg_replace_string (config, "xauthority", &sdl->xauthority, 0);
}

static char *parse_cmdline(XLU_Config *config)
{
    char *cmdline = NULL;
    const char *root = NULL, *extra = NULL, *buf = NULL;

    xlu_cfg_get_string (config, "cmdline", &buf, 0);
    xlu_cfg_get_string (config, "root", &root, 0);
    xlu_cfg_get_string (config, "extra", &extra, 0);

    if (buf) {
        cmdline = strdup(buf);
        if (root || extra)
            fprintf(stderr, "Warning: ignoring root= and extra= "
                    "in favour of cmdline=\n");
    } else {
        if (root) {
            if (asprintf(&cmdline, "root=%s %s", root, extra) == -1)
                cmdline = NULL;
        } else if (extra) {
            cmdline = strdup(extra);
        }
    }

    if ((buf || root || extra) && !cmdline) {
        fprintf(stderr, "Failed to allocate memory for cmdline\n");
        exit(1);
    }

    return cmdline;
}

static void parse_vcpu_affinity(libxl_domain_build_info *b_info,
                                XLU_ConfigList *cpus, const char *buf,
                                int num_cpus, bool is_hard)
{
    libxl_bitmap *vcpu_affinity_array;

    /*
     * If we are here, and buf is !NULL, we're dealing with a string. What
     * we do in this case is parse it, and copy the result in _all_ (up to
     * b_info->max_vcpus) the elements of the vcpu affinity array.
     *
     * If buf is NULL, we have a list, and what we do is putting in the
     * i-eth element of the vcpu affinity array the result of the parsing
     * of the i-eth entry of the list. If there are more vcpus than
     * entries, it is fine to just not touch the last array elements.
     */

    /* Silently ignore values corresponding to non existing vcpus */
    if (buf || num_cpus > b_info->max_vcpus)
        num_cpus = b_info->max_vcpus;

    if (is_hard) {
        b_info->num_vcpu_hard_affinity = num_cpus;
        b_info->vcpu_hard_affinity = xmalloc(num_cpus * sizeof(libxl_bitmap));
        vcpu_affinity_array = b_info->vcpu_hard_affinity;
    } else {
        b_info->num_vcpu_soft_affinity = num_cpus;
        b_info->vcpu_soft_affinity = xmalloc(num_cpus * sizeof(libxl_bitmap));
        vcpu_affinity_array = b_info->vcpu_soft_affinity;
    }

    if (!buf) {
        int j = 0;

        while ((buf = xlu_cfg_get_listitem(cpus, j)) != NULL && j < num_cpus) {
            libxl_bitmap_init(&vcpu_affinity_array[j]);
            if (libxl_cpu_bitmap_alloc(ctx, &vcpu_affinity_array[j], 0)) {
                fprintf(stderr, "Unable to allocate cpumap for vcpu %d\n", j);
                exit(1);
            }

            if (vcpupin_parse(buf, &vcpu_affinity_array[j]))
                exit(1);

            j++;
        }

        /* We have a list of cpumaps, disable automatic placement */
        libxl_defbool_set(&b_info->numa_placement, false);
    } else {
        int i;

        libxl_bitmap_init(&vcpu_affinity_array[0]);
        if (libxl_cpu_bitmap_alloc(ctx, &vcpu_affinity_array[0], 0)) {
            fprintf(stderr, "Unable to allocate cpumap for vcpu 0\n");
            exit(1);
        }

        if (vcpupin_parse(buf, &vcpu_affinity_array[0]))
            exit(1);

        for (i = 1; i < b_info->max_vcpus; i++) {
            libxl_bitmap_init(&vcpu_affinity_array[i]);
            if (libxl_cpu_bitmap_alloc(ctx, &vcpu_affinity_array[i], 0)) {
                fprintf(stderr, "Unable to allocate cpumap for vcpu %d\n", i);
                exit(1);
            }
            libxl_bitmap_copy(ctx, &vcpu_affinity_array[i],
                              &vcpu_affinity_array[0]);
        }

        libxl_defbool_set(&b_info->numa_placement, false);
    }
}

static void replace_string(char **str, const char *val)
{
    free(*str);
    *str = xstrdup(val);
}

static void parse_config_data(const char *config_source,
                              const char *config_data,
                              int config_len,
                              libxl_domain_config *d_config)
{
    const char *buf;
    long l;
    XLU_Config *config;
    XLU_ConfigList *cpus, *vbds, *nics, *pcis, *cvfbs, *cpuids, *vtpms;
    XLU_ConfigList *channels, *ioports, *irqs, *iomem, *viridian;
    int num_ioports, num_irqs, num_iomem, num_cpus, num_viridian;
    int pci_power_mgmt = 0;
    int pci_msitranslate = 0;
    int pci_permissive = 0;
    int pci_seize = 0;
    int i, e;
    char *kernel_basename;

    libxl_domain_create_info *c_info = &d_config->c_info;
    libxl_domain_build_info *b_info = &d_config->b_info;

    config= xlu_cfg_init(stderr, config_source);
    if (!config) {
        fprintf(stderr, "Failed to allocate for configuration\n");
        exit(1);
    }

    e= xlu_cfg_readdata(config, config_data, config_len);
    if (e) {
        fprintf(stderr, "Failed to parse config: %s\n", strerror(e));
        exit(1);
    }

    if (!xlu_cfg_get_string (config, "init_seclabel", &buf, 0))
        xlu_cfg_replace_string(config, "init_seclabel",
                               &c_info->ssid_label, 0);

    if (!xlu_cfg_get_string (config, "seclabel", &buf, 0)) {
        if (c_info->ssid_label)
            xlu_cfg_replace_string(config, "seclabel",
                                   &b_info->exec_ssid_label, 0);
        else
            xlu_cfg_replace_string(config, "seclabel",
                                   &c_info->ssid_label, 0);
    }

    libxl_defbool_set(&c_info->run_hotplug_scripts, run_hotplug_scripts);
    c_info->type = LIBXL_DOMAIN_TYPE_PV;
    if (!xlu_cfg_get_string (config, "builder", &buf, 0) &&
        !strncmp(buf, "hvm", strlen(buf)))
        c_info->type = LIBXL_DOMAIN_TYPE_HVM;

    xlu_cfg_get_defbool(config, "pvh", &c_info->pvh, 0);
    xlu_cfg_get_defbool(config, "hap", &c_info->hap, 0);

    if (xlu_cfg_replace_string (config, "name", &c_info->name, 0)) {
        fprintf(stderr, "Domain name must be specified.\n");
        exit(1);
    }

    if (!xlu_cfg_get_string (config, "uuid", &buf, 0) ) {
        if ( libxl_uuid_from_string(&c_info->uuid, buf) ) {
            fprintf(stderr, "Failed to parse UUID: %s\n", buf);
            exit(1);
        }
    }else{
        libxl_uuid_generate(&c_info->uuid);
    }

    xlu_cfg_get_defbool(config, "oos", &c_info->oos, 0);

    if (!xlu_cfg_get_string (config, "pool", &buf, 0))
        xlu_cfg_replace_string(config, "pool", &c_info->pool_name, 0);

    libxl_domain_build_info_init_type(b_info, c_info->type);
    if (blkdev_start)
        b_info->blkdev_start = strdup(blkdev_start);

    /* the following is the actual config parsing with overriding
     * values in the structures */
    if (!xlu_cfg_get_long (config, "cpu_weight", &l, 0))
        b_info->sched_params.weight = l;
    if (!xlu_cfg_get_long (config, "cap", &l, 0))
        b_info->sched_params.cap = l;
    if (!xlu_cfg_get_long (config, "period", &l, 0))
        b_info->sched_params.period = l;
    if (!xlu_cfg_get_long (config, "slice", &l, 0))
        b_info->sched_params.slice = l;
    if (!xlu_cfg_get_long (config, "latency", &l, 0))
        b_info->sched_params.latency = l;
    if (!xlu_cfg_get_long (config, "extratime", &l, 0))
        b_info->sched_params.extratime = l;

    if (!xlu_cfg_get_long (config, "vcpus", &l, 0)) {
        b_info->max_vcpus = l;

        if (libxl_cpu_bitmap_alloc(ctx, &b_info->avail_vcpus, l)) {
            fprintf(stderr, "Unable to allocate cpumap\n");
            exit(1);
        }
        libxl_bitmap_set_none(&b_info->avail_vcpus);
        while (l-- > 0)
            libxl_bitmap_set((&b_info->avail_vcpus), l);
    }

    if (!xlu_cfg_get_long (config, "maxvcpus", &l, 0))
        b_info->max_vcpus = l;

    buf = NULL;
    if (!xlu_cfg_get_list (config, "cpus", &cpus, &num_cpus, 1) ||
        !xlu_cfg_get_string (config, "cpus", &buf, 0))
        parse_vcpu_affinity(b_info, cpus, buf, num_cpus, /* is_hard */ true);

    buf = NULL;
    if (!xlu_cfg_get_list (config, "cpus_soft", &cpus, &num_cpus, 1) ||
        !xlu_cfg_get_string (config, "cpus_soft", &buf, 0))
        parse_vcpu_affinity(b_info, cpus, buf, num_cpus, false);

    if (!xlu_cfg_get_long (config, "memory", &l, 0)) {
        b_info->max_memkb = l * 1024;
        b_info->target_memkb = b_info->max_memkb;
    }

    if (!xlu_cfg_get_long (config, "maxmem", &l, 0))
        b_info->max_memkb = l * 1024;

    libxl_defbool_set(&b_info->claim_mode, claim_mode);

    if (xlu_cfg_get_string (config, "on_poweroff", &buf, 0))
        buf = "destroy";
    if (!parse_action_on_shutdown(buf, &d_config->on_poweroff)) {
        fprintf(stderr, "Unknown on_poweroff action \"%s\" specified\n", buf);
        exit(1);
    }

    if (xlu_cfg_get_string (config, "on_reboot", &buf, 0))
        buf = "restart";
    if (!parse_action_on_shutdown(buf, &d_config->on_reboot)) {
        fprintf(stderr, "Unknown on_reboot action \"%s\" specified\n", buf);
        exit(1);
    }

    if (xlu_cfg_get_string (config, "on_watchdog", &buf, 0))
        buf = "destroy";
    if (!parse_action_on_shutdown(buf, &d_config->on_watchdog)) {
        fprintf(stderr, "Unknown on_watchdog action \"%s\" specified\n", buf);
        exit(1);
    }


    if (xlu_cfg_get_string (config, "on_crash", &buf, 0))
        buf = "destroy";
    if (!parse_action_on_shutdown(buf, &d_config->on_crash)) {
        fprintf(stderr, "Unknown on_crash action \"%s\" specified\n", buf);
        exit(1);
    }

    /* libxl_get_required_shadow_memory() must be called after final values
     * (default or specified) for vcpus and memory are set, because the
     * calculation depends on those values. */
    b_info->shadow_memkb = !xlu_cfg_get_long(config, "shadow_memory", &l, 0)
        ? l * 1024
        : libxl_get_required_shadow_memory(b_info->max_memkb,
                                           b_info->max_vcpus);

    xlu_cfg_get_defbool(config, "nomigrate", &b_info->disable_migrate, 0);

    if (!xlu_cfg_get_long(config, "tsc_mode", &l, 1)) {
        const char *s = libxl_tsc_mode_to_string(l);
        fprintf(stderr, "WARNING: specifying \"tsc_mode\" as an integer is deprecated. "
                "Please use the named parameter variant. %s%s%s\n",
                s ? "e.g. tsc_mode=\"" : "",
                s ? s : "",
                s ? "\"" : "");

        if (l < LIBXL_TSC_MODE_DEFAULT ||
            l > LIBXL_TSC_MODE_NATIVE_PARAVIRT) {
            fprintf(stderr, "ERROR: invalid value %ld for \"tsc_mode\"\n", l);
            exit (1);
        }
        b_info->tsc_mode = l;
    } else if (!xlu_cfg_get_string(config, "tsc_mode", &buf, 0)) {
        fprintf(stderr, "got a tsc mode string: \"%s\"\n", buf);
        if (libxl_tsc_mode_from_string(buf, &b_info->tsc_mode)) {
            fprintf(stderr, "ERROR: invalid value \"%s\" for \"tsc_mode\"\n",
                    buf);
            exit (1);
        }
    }

    if (!xlu_cfg_get_long(config, "rtc_timeoffset", &l, 0))
        b_info->rtc_timeoffset = l;

    if (!xlu_cfg_get_long(config, "vncviewer", &l, 0))
        fprintf(stderr, "WARNING: ignoring \"vncviewer\" option. "
                "Use \"-V\" option of \"xl create\" to automatically spawn vncviewer.\n");

    xlu_cfg_get_defbool(config, "localtime", &b_info->localtime, 0);

    if (!xlu_cfg_get_long (config, "videoram", &l, 0))
        b_info->video_memkb = l * 1024;

    if (!xlu_cfg_get_long(config, "max_event_channels", &l, 0))
        b_info->event_channels = l;

    xlu_cfg_replace_string (config, "kernel", &b_info->kernel, 0);
    xlu_cfg_replace_string (config, "ramdisk", &b_info->ramdisk, 0);
    b_info->cmdline = parse_cmdline(config);

    xlu_cfg_get_defbool(config, "driver_domain", &c_info->driver_domain, 0);

    switch(b_info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        kernel_basename = libxl_basename(b_info->kernel);
        if (!strcmp(kernel_basename, "hvmloader")) {
            fprintf(stderr, "WARNING: you seem to be using \"kernel\" "
                    "directive to override HVM guest firmware. Ignore "
                    "that. Use \"firmware_override\" instead if you "
                    "really want a non-default firmware\n");
            b_info->kernel = NULL;
        }
        free(kernel_basename);

        xlu_cfg_replace_string (config, "firmware_override",
                                &b_info->u.hvm.firmware, 0);
        if (!xlu_cfg_get_string(config, "bios", &buf, 0) &&
            libxl_bios_type_from_string(buf, &b_info->u.hvm.bios)) {
                fprintf(stderr, "ERROR: invalid value \"%s\" for \"bios\"\n",
                    buf);
                exit (1);
        }

        xlu_cfg_get_defbool(config, "pae", &b_info->u.hvm.pae, 0);
        xlu_cfg_get_defbool(config, "apic", &b_info->u.hvm.apic, 0);
        xlu_cfg_get_defbool(config, "acpi", &b_info->u.hvm.acpi, 0);
        xlu_cfg_get_defbool(config, "acpi_s3", &b_info->u.hvm.acpi_s3, 0);
        xlu_cfg_get_defbool(config, "acpi_s4", &b_info->u.hvm.acpi_s4, 0);
        xlu_cfg_get_defbool(config, "nx", &b_info->u.hvm.nx, 0);
        xlu_cfg_get_defbool(config, "hpet", &b_info->u.hvm.hpet, 0);
        xlu_cfg_get_defbool(config, "vpt_align", &b_info->u.hvm.vpt_align, 0);

        switch (xlu_cfg_get_list(config, "viridian",
                                 &viridian, &num_viridian, 1))
        {
        case 0: /* Success */
            if (num_viridian) {
                libxl_bitmap_alloc(ctx, &b_info->u.hvm.viridian_enable,
                                   LIBXL_BUILDINFO_HVM_VIRIDIAN_ENABLE_DISABLE_WIDTH);
                libxl_bitmap_alloc(ctx, &b_info->u.hvm.viridian_disable,
                                   LIBXL_BUILDINFO_HVM_VIRIDIAN_ENABLE_DISABLE_WIDTH);
            }
            for (i = 0; i < num_viridian; i++) {
                libxl_viridian_enlightenment v;

                buf = xlu_cfg_get_listitem(viridian, i);
                if (strcmp(buf, "all") == 0)
                    libxl_bitmap_set_any(&b_info->u.hvm.viridian_enable);
                else if (strcmp(buf, "defaults") == 0)
                    libxl_defbool_set(&b_info->u.hvm.viridian, true);
                else {
                    libxl_bitmap *s = &b_info->u.hvm.viridian_enable;
                    libxl_bitmap *r = &b_info->u.hvm.viridian_disable;

                    if (*buf == '!') {
                        s = &b_info->u.hvm.viridian_disable;
                        r = &b_info->u.hvm.viridian_enable;
                        buf++;
                    }

                    e = libxl_viridian_enlightenment_from_string(buf, &v);
                    if (e) {
                        fprintf(stderr,
                                "xl: unknown viridian enlightenment '%s'\n",
                                buf);
                        exit(-ERROR_FAIL);
                    }

                    libxl_bitmap_set(s, v);
                    libxl_bitmap_reset(r, v);
                }
            }
            break;
        case ESRCH: break; /* Option not present */
        case EINVAL:
            xlu_cfg_get_defbool(config, "viridian", &b_info->u.hvm.viridian, 1);
            break;
        default:
            fprintf(stderr,"xl: Unable to parse viridian enlightenments.\n");
            exit(-ERROR_FAIL);
        }

        if (!xlu_cfg_get_long(config, "mmio_hole", &l, 0)) {
            uint64_t mmio_hole_size;

            b_info->u.hvm.mmio_hole_memkb = l * 1024;
            mmio_hole_size = b_info->u.hvm.mmio_hole_memkb * 1024;
            if (mmio_hole_size < HVM_BELOW_4G_MMIO_LENGTH ||
                mmio_hole_size > HVM_BELOW_4G_MMIO_START) {
                fprintf(stderr,
                        "ERROR: invalid value %ld for \"mmio_hole\"\n", l);
                exit (1);
            }
        }
        if (!xlu_cfg_get_long(config, "timer_mode", &l, 1)) {
            const char *s = libxl_timer_mode_to_string(l);
            fprintf(stderr, "WARNING: specifying \"timer_mode\" as an integer is deprecated. "
                    "Please use the named parameter variant. %s%s%s\n",
                    s ? "e.g. timer_mode=\"" : "",
                    s ? s : "",
                    s ? "\"" : "");

            if (l < LIBXL_TIMER_MODE_DELAY_FOR_MISSED_TICKS ||
                l > LIBXL_TIMER_MODE_ONE_MISSED_TICK_PENDING) {
                fprintf(stderr, "ERROR: invalid value %ld for \"timer_mode\"\n", l);
                exit (1);
            }
            b_info->u.hvm.timer_mode = l;
        } else if (!xlu_cfg_get_string(config, "timer_mode", &buf, 0)) {
            if (libxl_timer_mode_from_string(buf, &b_info->u.hvm.timer_mode)) {
                fprintf(stderr, "ERROR: invalid value \"%s\" for \"timer_mode\"\n",
                        buf);
                exit (1);
            }
        }

        xlu_cfg_get_defbool(config, "nestedhvm", &b_info->u.hvm.nested_hvm, 0);

        xlu_cfg_replace_string(config, "smbios_firmware",
                               &b_info->u.hvm.smbios_firmware, 0);
        xlu_cfg_replace_string(config, "acpi_firmware",
                               &b_info->u.hvm.acpi_firmware, 0);

        if (!xlu_cfg_get_string(config, "ms_vm_genid", &buf, 0)) {
            if (!strcmp(buf, "generate")) {
                e = libxl_ms_vm_genid_generate(ctx, &b_info->u.hvm.ms_vm_genid);
                if (e) {
                    fprintf(stderr, "ERROR: failed to generate a VM Generation ID\n");
                    exit(1);
                }
            } else if (!strcmp(buf, "none")) {
                ;
            } else {
                    fprintf(stderr, "ERROR: \"ms_vm_genid\" option must be \"generate\" or \"none\"\n");
                    exit(1);
            }
        }
        break;
    case LIBXL_DOMAIN_TYPE_PV:
    {
        xlu_cfg_replace_string (config, "bootloader", &b_info->u.pv.bootloader, 0);
        switch (xlu_cfg_get_list_as_string_list(config, "bootloader_args",
                                      &b_info->u.pv.bootloader_args, 1))
        {

        case 0: break; /* Success */
        case ESRCH: break; /* Option not present */
        case EINVAL:
            if (!xlu_cfg_get_string(config, "bootloader_args", &buf, 0)) {

                fprintf(stderr, "WARNING: Specifying \"bootloader_args\""
                        " as a string is deprecated. "
                        "Please use a list of arguments.\n");
                split_string_into_string_list(buf, " \t\n",
                                              &b_info->u.pv.bootloader_args);
            }
            break;
        default:
            fprintf(stderr,"xl: Unable to parse bootloader_args.\n");
            exit(-ERROR_FAIL);
        }

        if (!b_info->u.pv.bootloader && !b_info->kernel) {
            fprintf(stderr, "Neither kernel nor bootloader specified\n");
            exit(1);
        }

        break;
    }
    default:
        abort();
    }

    if (!xlu_cfg_get_list(config, "ioports", &ioports, &num_ioports, 0)) {
        b_info->num_ioports = num_ioports;
        b_info->ioports = calloc(num_ioports, sizeof(*b_info->ioports));
        if (b_info->ioports == NULL) {
            fprintf(stderr, "unable to allocate memory for ioports\n");
            exit(-1);
        }

        for (i = 0; i < num_ioports; i++) {
            const char *buf2;
            char *ep;
            uint32_t start, end;
            unsigned long ul;

            buf = xlu_cfg_get_listitem (ioports, i);
            if (!buf) {
                fprintf(stderr,
                        "xl: Unable to get element #%d in ioport list\n", i);
                exit(1);
            }
            ul = strtoul(buf, &ep, 16);
            if (ep == buf) {
                fprintf(stderr, "xl: Invalid argument parsing ioport: %s\n",
                        buf);
                exit(1);
            }
            if (ul >= UINT32_MAX) {
                fprintf(stderr, "xl: ioport %lx too big\n", ul);
                exit(1);
            }
            start = end = ul;

            if (*ep == '-') {
                buf2 = ep + 1;
                ul = strtoul(buf2, &ep, 16);
                if (ep == buf2 || *ep != '\0' || start > end) {
                    fprintf(stderr,
                            "xl: Invalid argument parsing ioport: %s\n", buf);
                    exit(1);
                }
                if (ul >= UINT32_MAX) {
                    fprintf(stderr, "xl: ioport %lx too big\n", ul);
                    exit(1);
                }
                end = ul;
            } else if ( *ep != '\0' )
                fprintf(stderr,
                        "xl: Invalid argument parsing ioport: %s\n", buf);
            b_info->ioports[i].first = start;
            b_info->ioports[i].number = end - start + 1;
        }
    }

    if (!xlu_cfg_get_list(config, "irqs", &irqs, &num_irqs, 0)) {
        b_info->num_irqs = num_irqs;
        b_info->irqs = calloc(num_irqs, sizeof(*b_info->irqs));
        if (b_info->irqs == NULL) {
            fprintf(stderr, "unable to allocate memory for ioports\n");
            exit(-1);
        }
        for (i = 0; i < num_irqs; i++) {
            char *ep;
            unsigned long ul;
            buf = xlu_cfg_get_listitem (irqs, i);
            if (!buf) {
                fprintf(stderr,
                        "xl: Unable to get element %d in irq list\n", i);
                exit(1);
            }
            ul = strtoul(buf, &ep, 10);
            if (ep == buf) {
                fprintf(stderr,
                        "xl: Invalid argument parsing irq: %s\n", buf);
                exit(1);
            }
            if (ul >= UINT32_MAX) {
                fprintf(stderr, "xl: irq %lx too big\n", ul);
                exit(1);
            }
            b_info->irqs[i] = ul;
        }
    }

    if (!xlu_cfg_get_list(config, "iomem", &iomem, &num_iomem, 0)) {
        int ret;
        b_info->num_iomem = num_iomem;
        b_info->iomem = calloc(num_iomem, sizeof(*b_info->iomem));
        if (b_info->iomem == NULL) {
            fprintf(stderr, "unable to allocate memory for iomem\n");
            exit(-1);
        }
        for (i = 0; i < num_iomem; i++) {
            buf = xlu_cfg_get_listitem (iomem, i);
            if (!buf) {
                fprintf(stderr,
                        "xl: Unable to get element %d in iomem list\n", i);
                exit(1);
            }
            libxl_iomem_range_init(&b_info->iomem[i]);
            ret = sscanf(buf, "%" SCNx64",%" SCNx64"@%" SCNx64,
                         &b_info->iomem[i].start,
                         &b_info->iomem[i].number,
                         &b_info->iomem[i].gfn);
            if (ret < 2) {
                fprintf(stderr,
                        "xl: Invalid argument parsing iomem: %s\n", buf);
                exit(1);
            }
        }
    }



    if (!xlu_cfg_get_list (config, "disk", &vbds, 0, 0)) {
        d_config->num_disks = 0;
        d_config->disks = NULL;
        while ((buf = xlu_cfg_get_listitem (vbds, d_config->num_disks)) != NULL) {
            libxl_device_disk *disk;
            char *buf2 = strdup(buf);

            d_config->disks = (libxl_device_disk *) realloc(d_config->disks, sizeof (libxl_device_disk) * (d_config->num_disks + 1));
            disk = d_config->disks + d_config->num_disks;
            parse_disk_config(&config, buf2, disk);

            free(buf2);
            d_config->num_disks++;
        }
    }

    if (!xlu_cfg_get_list(config, "vtpm", &vtpms, 0, 0)) {
        d_config->num_vtpms = 0;
        d_config->vtpms = NULL;
        while ((buf = xlu_cfg_get_listitem (vtpms, d_config->num_vtpms)) != NULL) {
            libxl_device_vtpm *vtpm;
            char * buf2 = strdup(buf);
            char *p, *p2;
            bool got_backend = false;

            d_config->vtpms = (libxl_device_vtpm *) realloc(d_config->vtpms,
                  sizeof(libxl_device_vtpm) * (d_config->num_vtpms+1));
            vtpm = d_config->vtpms + d_config->num_vtpms;
            libxl_device_vtpm_init(vtpm);
            vtpm->devid = d_config->num_vtpms;

            p = strtok(buf2, ",");
            if(p) {
               do {
                  while(*p == ' ')
                     ++p;
                  if ((p2 = strchr(p, '=')) == NULL)
                     break;
                  *p2 = '\0';
                  if (!strcmp(p, "backend")) {
                     vtpm->backend_domname = strdup(p2 + 1);
                     got_backend = true;
                  } else if(!strcmp(p, "uuid")) {
                     if( libxl_uuid_from_string(&vtpm->uuid, p2 + 1) ) {
                        fprintf(stderr,
                              "Failed to parse vtpm UUID: %s\n", p2 + 1);
                        exit(1);
                    }
                  } else {
                     fprintf(stderr, "Unknown string `%s' in vtpm spec\n", p);
                     exit(1);
                  }
               } while ((p = strtok(NULL, ",")) != NULL);
            }
            if(!got_backend) {
               fprintf(stderr, "vtpm spec missing required backend field!\n");
               exit(1);
            }
            free(buf2);
            d_config->num_vtpms++;
        }
    }

    if (!xlu_cfg_get_list (config, "channel", &channels, 0, 0)) {
        d_config->num_channels = 0;
        d_config->channels = NULL;
        while ((buf = xlu_cfg_get_listitem (channels,
                d_config->num_channels)) != NULL) {
            libxl_device_channel *chn;
            libxl_string_list pairs;
            char *path = NULL;
            int len;

            chn = ARRAY_EXTEND_INIT(d_config->channels, d_config->num_channels,
                                   libxl_device_channel_init);

            split_string_into_string_list(buf, ",", &pairs);
            len = libxl_string_list_length(&pairs);
            for (i = 0; i < len; i++) {
                char *key, *key_untrimmed, *value, *value_untrimmed;
                int rc;
                rc = split_string_into_pair(pairs[i], "=",
                                            &key_untrimmed,
                                            &value_untrimmed);
                if (rc != 0) {
                    fprintf(stderr, "failed to parse channel configuration: %s",
                            pairs[i]);
                    exit(1);
                }
                trim(isspace, key_untrimmed, &key);
                trim(isspace, value_untrimmed, &value);

                if (!strcmp(key, "backend")) {
                    replace_string(&chn->backend_domname, value);
                } else if (!strcmp(key, "name")) {
                    replace_string(&chn->name, value);
                } else if (!strcmp(key, "path")) {
                    replace_string(&path, value);
                } else if (!strcmp(key, "connection")) {
                    if (!strcmp(value, "pty")) {
                        chn->connection = LIBXL_CHANNEL_CONNECTION_PTY;
                    } else if (!strcmp(value, "socket")) {
                        chn->connection = LIBXL_CHANNEL_CONNECTION_SOCKET;
                    } else {
                        fprintf(stderr, "unknown channel connection '%s'\n",
                                value);
                        exit(1);
                    }
                } else {
                    fprintf(stderr, "unknown channel parameter '%s',"
                                  " ignoring\n", key);
                }
                free(key);
                free(key_untrimmed);
                free(value);
                free(value_untrimmed);
            }
            switch (chn->connection) {
            case LIBXL_CHANNEL_CONNECTION_UNKNOWN:
                fprintf(stderr, "channel has unknown 'connection'\n");
                exit(1);
            case LIBXL_CHANNEL_CONNECTION_SOCKET:
                if (!path) {
                    fprintf(stderr, "channel connection 'socket' requires path=..\n");
                    exit(1);
                }
                chn->u.socket.path = xstrdup(path);
                break;
            case LIBXL_CHANNEL_CONNECTION_PTY:
                /* Nothing to do since PTY has no arguments */
                break;
            default:
                fprintf(stderr, "unknown channel connection: %d",
                        chn->connection);
                exit(1);
            }
            libxl_string_list_dispose(&pairs);
            free(path);
        }
    }

    if (!xlu_cfg_get_list (config, "vif", &nics, 0, 0)) {
        d_config->num_nics = 0;
        d_config->nics = NULL;
        while ((buf = xlu_cfg_get_listitem (nics, d_config->num_nics)) != NULL) {
            libxl_device_nic *nic;
            char *buf2 = strdup(buf);
            char *p, *p2;

            d_config->nics = (libxl_device_nic *) realloc(d_config->nics, sizeof (libxl_device_nic) * (d_config->num_nics+1));
            nic = d_config->nics + d_config->num_nics;
            libxl_device_nic_init(nic);
            nic->devid = d_config->num_nics;
            set_default_nic_values(nic);

            p = strtok(buf2, ",");
            if (!p)
                goto skip_nic;
            do {
                while (*p == ' ')
                    p++;
                if ((p2 = strchr(p, '=')) == NULL)
                    break;
                *p2 = '\0';
                if (!strcmp(p, "model")) {
                    free(nic->model);
                    nic->model = strdup(p2 + 1);
                } else if (!strcmp(p, "mac")) {
                    char *p3 = p2 + 1;
                    *(p3 + 2) = '\0';
                    nic->mac[0] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    nic->mac[1] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    nic->mac[2] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    nic->mac[3] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    nic->mac[4] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    nic->mac[5] = strtol(p3, NULL, 16);
                } else if (!strcmp(p, "bridge")) {
                    free(nic->bridge);
                    nic->bridge = strdup(p2 + 1);
                } else if (!strcmp(p, "type")) {
                    if (!strcmp(p2 + 1, "ioemu"))
                        nic->nictype = LIBXL_NIC_TYPE_VIF_IOEMU;
                    else
                        nic->nictype = LIBXL_NIC_TYPE_VIF;
                } else if (!strcmp(p, "ip")) {
                    free(nic->ip);
                    nic->ip = strdup(p2 + 1);
                } else if (!strcmp(p, "script")) {
                    free(nic->script);
                    nic->script = strdup(p2 + 1);
                } else if (!strcmp(p, "vifname")) {
                    free(nic->ifname);
                    nic->ifname = strdup(p2 + 1);
                } else if (!strcmp(p, "backend")) {
                    free(nic->backend_domname);
                    nic->backend_domname = strdup(p2 + 1);
                } else if (!strcmp(p, "rate")) {
                    parse_vif_rate(&config, (p2 + 1), nic);
                } else if (!strcmp(p, "accel")) {
                    fprintf(stderr, "the accel parameter for vifs is currently not supported\n");
                } else if (!strcmp(p, "netdev")) {
                    fprintf(stderr, "the netdev parameter is deprecated, "
                                    "please use gatewaydev instead\n");
                    free(nic->gatewaydev);
                    nic->gatewaydev = strdup(p2 + 1);
                } else if (!strcmp(p, "gatewaydev")) {
                    free(nic->gatewaydev);
                    nic->gatewaydev = strdup(p2 + 1);
                }
            } while ((p = strtok(NULL, ",")) != NULL);
skip_nic:
            free(buf2);
            d_config->num_nics++;
        }
    }

    if (!xlu_cfg_get_list(config, "vif2", NULL, 0, 0)) {
        fprintf(stderr, "WARNING: vif2: netchannel2 is deprecated and not supported by xl\n");
    }

    d_config->num_vfbs = 0;
    d_config->num_vkbs = 0;
    d_config->vfbs = NULL;
    d_config->vkbs = NULL;

    if (!xlu_cfg_get_list (config, "vfb", &cvfbs, 0, 0)) {
        while ((buf = xlu_cfg_get_listitem (cvfbs, d_config->num_vfbs)) != NULL) {
            libxl_device_vfb *vfb;
            libxl_device_vkb *vkb;

            char *buf2 = strdup(buf);
            char *p, *p2;

            vfb = ARRAY_EXTEND_INIT(d_config->vfbs, d_config->num_vfbs,
                                    libxl_device_vfb_init);

            vkb = ARRAY_EXTEND_INIT(d_config->vkbs, d_config->num_vkbs,
                                    libxl_device_vkb_init);

            p = strtok(buf2, ",");
            if (!p)
                goto skip_vfb;
            do {
                while (*p == ' ')
                    p++;
                if ((p2 = strchr(p, '=')) == NULL)
                    break;
                *p2 = '\0';
                if (!strcmp(p, "vnc")) {
                    libxl_defbool_set(&vfb->vnc.enable, atoi(p2 + 1));
                } else if (!strcmp(p, "vnclisten")) {
                    free(vfb->vnc.listen);
                    vfb->vnc.listen = strdup(p2 + 1);
                } else if (!strcmp(p, "vncpasswd")) {
                    free(vfb->vnc.passwd);
                    vfb->vnc.passwd = strdup(p2 + 1);
                } else if (!strcmp(p, "vncdisplay")) {
                    vfb->vnc.display = atoi(p2 + 1);
                } else if (!strcmp(p, "vncunused")) {
                    libxl_defbool_set(&vfb->vnc.findunused, atoi(p2 + 1));
                } else if (!strcmp(p, "keymap")) {
                    free(vfb->keymap);
                    vfb->keymap = strdup(p2 + 1);
                } else if (!strcmp(p, "sdl")) {
                    libxl_defbool_set(&vfb->sdl.enable, atoi(p2 + 1));
                } else if (!strcmp(p, "opengl")) {
                    libxl_defbool_set(&vfb->sdl.opengl, atoi(p2 + 1));
                } else if (!strcmp(p, "display")) {
                    free(vfb->sdl.display);
                    vfb->sdl.display = strdup(p2 + 1);
                } else if (!strcmp(p, "xauthority")) {
                    free(vfb->sdl.xauthority);
                    vfb->sdl.xauthority = strdup(p2 + 1);
                }
            } while ((p = strtok(NULL, ",")) != NULL);

skip_vfb:
            free(buf2);
        }
    }

    if (!xlu_cfg_get_long (config, "pci_msitranslate", &l, 0))
        pci_msitranslate = l;

    if (!xlu_cfg_get_long (config, "pci_power_mgmt", &l, 0))
        pci_power_mgmt = l;

    if (!xlu_cfg_get_long (config, "pci_permissive", &l, 0))
        pci_permissive = l;

    if (!xlu_cfg_get_long (config, "pci_seize", &l, 0))
        pci_seize = l;

    /* To be reworked (automatically enabled) once the auto ballooning
     * after guest starts is done (with PCI devices passed in). */
    if (c_info->type == LIBXL_DOMAIN_TYPE_PV) {
        xlu_cfg_get_defbool(config, "e820_host", &b_info->u.pv.e820_host, 0);
    }

    if (!xlu_cfg_get_list (config, "pci", &pcis, 0, 0)) {
        d_config->num_pcidevs = 0;
        d_config->pcidevs = NULL;
        for(i = 0; (buf = xlu_cfg_get_listitem (pcis, i)) != NULL; i++) {
            libxl_device_pci *pcidev;

            d_config->pcidevs = (libxl_device_pci *) realloc(d_config->pcidevs, sizeof (libxl_device_pci) * (d_config->num_pcidevs + 1));
            pcidev = d_config->pcidevs + d_config->num_pcidevs;
            libxl_device_pci_init(pcidev);

            pcidev->msitranslate = pci_msitranslate;
            pcidev->power_mgmt = pci_power_mgmt;
            pcidev->permissive = pci_permissive;
            pcidev->seize = pci_seize;
            if (!xlu_pci_parse_bdf(config, pcidev, buf))
                d_config->num_pcidevs++;
        }
        if (d_config->num_pcidevs && c_info->type == LIBXL_DOMAIN_TYPE_PV)
            libxl_defbool_set(&b_info->u.pv.e820_host, true);
    }

    switch (xlu_cfg_get_list(config, "cpuid", &cpuids, 0, 1)) {
    case 0:
        {
            const char *errstr;

            for (i = 0; (buf = xlu_cfg_get_listitem(cpuids, i)) != NULL; i++) {
                e = libxl_cpuid_parse_config_xend(&b_info->cpuid, buf);
                switch (e) {
                case 0: continue;
                case 1:
                    errstr = "illegal leaf number";
                    break;
                case 2:
                    errstr = "illegal subleaf number";
                    break;
                case 3:
                    errstr = "missing colon";
                    break;
                case 4:
                    errstr = "invalid register name (must be e[abcd]x)";
                    break;
                case 5:
                    errstr = "policy string must be exactly 32 characters long";
                    break;
                default:
                    errstr = "unknown error";
                    break;
                }
                fprintf(stderr, "while parsing CPUID line: \"%s\":\n", buf);
                fprintf(stderr, "  error #%i: %s\n", e, errstr);
            }
        }
        break;
    case EINVAL:    /* config option is not a list, parse as a string */
        if (!xlu_cfg_get_string(config, "cpuid", &buf, 0)) {
            char *buf2, *p, *strtok_ptr = NULL;
            const char *errstr;

            buf2 = strdup(buf);
            p = strtok_r(buf2, ",", &strtok_ptr);
            if (p == NULL) {
                free(buf2);
                break;
            }
            if (strcmp(p, "host")) {
                fprintf(stderr, "while parsing CPUID string: \"%s\":\n", buf);
                fprintf(stderr, "  error: first word must be \"host\"\n");
                free(buf2);
                break;
            }
            for (p = strtok_r(NULL, ",", &strtok_ptr); p != NULL;
                 p = strtok_r(NULL, ",", &strtok_ptr)) {
                e = libxl_cpuid_parse_config(&b_info->cpuid, p);
                switch (e) {
                case 0: continue;
                case 1:
                    errstr = "missing \"=\" in key=value";
                    break;
                case 2:
                    errstr = "unknown CPUID flag name";
                    break;
                case 3:
                    errstr = "illegal CPUID value (must be: [0|1|x|k|s])";
                    break;
                default:
                    errstr = "unknown error";
                    break;
                }
                fprintf(stderr, "while parsing CPUID flag: \"%s\":\n", p);
                fprintf(stderr, "  error #%i: %s\n", e, errstr);
            }
            free(buf2);
        }
        break;
    default:
        break;
    }

    /* parse device model arguments, this works for pv, hvm and stubdom */
    if (!xlu_cfg_get_string (config, "device_model", &buf, 0)) {
        fprintf(stderr,
                "WARNING: ignoring device_model directive.\n"
                "WARNING: Use \"device_model_override\" instead if you"
                " really want a non-default device_model\n");
        if (strstr(buf, "stubdom-dm")) {
            if (c_info->type == LIBXL_DOMAIN_TYPE_HVM)
                fprintf(stderr, "WARNING: Or use"
                        " \"device_model_stubdomain_override\" if you "
                        " want to enable stubdomains\n");
            else
                fprintf(stderr, "WARNING: ignoring"
                        " \"device_model_stubdomain_override\" directive"
                        " for pv guest\n");
        }
    }


    xlu_cfg_replace_string (config, "device_model_override",
                            &b_info->device_model, 0);
    if (!xlu_cfg_get_string (config, "device_model_version", &buf, 0)) {
        if (!strcmp(buf, "qemu-xen-traditional")) {
            b_info->device_model_version
                = LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
        } else if (!strcmp(buf, "qemu-xen")) {
            b_info->device_model_version
                = LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN;
        } else {
            fprintf(stderr,
                    "Unknown device_model_version \"%s\" specified\n", buf);
            exit(1);
        }
    } else if (b_info->device_model)
        fprintf(stderr, "WARNING: device model override given without specific DM version\n");
    xlu_cfg_get_defbool (config, "device_model_stubdomain_override",
                         &b_info->device_model_stubdomain, 0);

    if (!xlu_cfg_get_string (config, "device_model_stubdomain_seclabel",
                             &buf, 0))
        xlu_cfg_replace_string(config, "device_model_stubdomain_seclabel",
                               &b_info->device_model_ssid_label, 0);

#define parse_extra_args(type)                                            \
    e = xlu_cfg_get_list_as_string_list(config, "device_model_args"#type, \
                                    &b_info->extra##type, 0);            \
    if (e && e != ESRCH) {                                                \
        fprintf(stderr,"xl: Unable to parse device_model_args"#type".\n");\
        exit(-ERROR_FAIL);                                                \
    }

    /* parse extra args for qemu, common to both pv, hvm */
    parse_extra_args();

    /* parse extra args dedicated to pv */
    parse_extra_args(_pv);

    /* parse extra args dedicated to hvm */
    parse_extra_args(_hvm);

#undef parse_extra_args

    /* If we've already got vfb=[] for PV guest then ignore top level
     * VNC config. */
    if (c_info->type == LIBXL_DOMAIN_TYPE_PV && !d_config->num_vfbs) {
        long vnc_enabled = 0;

        if (!xlu_cfg_get_long (config, "vnc", &l, 0))
            vnc_enabled = l;

        if (vnc_enabled) {
            libxl_device_vfb *vfb;
            libxl_device_vkb *vkb;

            vfb = ARRAY_EXTEND_INIT(d_config->vfbs, d_config->num_vfbs,
                                    libxl_device_vfb_init);

            vkb = ARRAY_EXTEND_INIT(d_config->vkbs, d_config->num_vkbs,
                                    libxl_device_vkb_init);

            parse_top_level_vnc_options(config, &vfb->vnc);
            parse_top_level_sdl_options(config, &vfb->sdl);
            xlu_cfg_replace_string (config, "keymap", &vfb->keymap, 0);
        }
    } else {
        parse_top_level_vnc_options(config, &b_info->u.hvm.vnc);
        parse_top_level_sdl_options(config, &b_info->u.hvm.sdl);
    }

    if (c_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        if (!xlu_cfg_get_string (config, "vga", &buf, 0)) {
            if (!strcmp(buf, "stdvga")) {
                b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_STD;
            } else if (!strcmp(buf, "cirrus")) {
                b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_CIRRUS;
            } else if (!strcmp(buf, "none")) {
                b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_NONE;
            } else {
                fprintf(stderr, "Unknown vga \"%s\" specified\n", buf);
                exit(1);
            }
        } else if (!xlu_cfg_get_long(config, "stdvga", &l, 0))
            b_info->u.hvm.vga.kind = l ? LIBXL_VGA_INTERFACE_TYPE_STD :
                                         LIBXL_VGA_INTERFACE_TYPE_CIRRUS;

        xlu_cfg_replace_string (config, "keymap", &b_info->u.hvm.keymap, 0);
        xlu_cfg_get_defbool (config, "spice", &b_info->u.hvm.spice.enable, 0);
        if (!xlu_cfg_get_long (config, "spiceport", &l, 0))
            b_info->u.hvm.spice.port = l;
        if (!xlu_cfg_get_long (config, "spicetls_port", &l, 0))
            b_info->u.hvm.spice.tls_port = l;
        xlu_cfg_replace_string (config, "spicehost",
                                &b_info->u.hvm.spice.host, 0);
        xlu_cfg_get_defbool(config, "spicedisable_ticketing",
                            &b_info->u.hvm.spice.disable_ticketing, 0);
        xlu_cfg_replace_string (config, "spicepasswd",
                                &b_info->u.hvm.spice.passwd, 0);
        xlu_cfg_get_defbool(config, "spiceagent_mouse",
                            &b_info->u.hvm.spice.agent_mouse, 0);
        xlu_cfg_get_defbool(config, "spicevdagent",
                            &b_info->u.hvm.spice.vdagent, 0);
        xlu_cfg_get_defbool(config, "spice_clipboard_sharing",
                            &b_info->u.hvm.spice.clipboard_sharing, 0);
        if (!xlu_cfg_get_long (config, "spiceusbredirection", &l, 0))
            b_info->u.hvm.spice.usbredirection = l;
        xlu_cfg_get_defbool(config, "nographic", &b_info->u.hvm.nographic, 0);
        xlu_cfg_get_defbool(config, "gfx_passthru",
                            &b_info->u.hvm.gfx_passthru, 0);
        switch (xlu_cfg_get_list_as_string_list(config, "serial",
                                                &b_info->u.hvm.serial_list,
                                                1))
        {

        case 0: break; /* Success */
        case ESRCH: break; /* Option not present */
        case EINVAL:
            /* If it's not a valid list, try reading it as an atom,
             * falling through to an error if it fails */
            if (!xlu_cfg_replace_string(config, "serial",
                                        &b_info->u.hvm.serial, 0))
                break;
            /* FALLTHRU */
        default:
            fprintf(stderr,"xl: Unable to parse serial.\n");
            exit(-ERROR_FAIL);
        }
        xlu_cfg_replace_string (config, "boot", &b_info->u.hvm.boot, 0);
        xlu_cfg_get_defbool(config, "usb", &b_info->u.hvm.usb, 0);
        if (!xlu_cfg_get_long (config, "usbversion", &l, 0))
            b_info->u.hvm.usbversion = l;
        switch (xlu_cfg_get_list_as_string_list(config, "usbdevice",
                                                &b_info->u.hvm.usbdevice_list,
                                                1))
        {

        case 0: break; /* Success */
        case ESRCH: break; /* Option not present */
        case EINVAL:
            /* If it's not a valid list, try reading it as an atom,
             * falling through to an error if it fails */
            if (!xlu_cfg_replace_string(config, "usbdevice",
                                        &b_info->u.hvm.usbdevice, 0))
                break;
            /* FALLTHRU */
        default:
            fprintf(stderr,"xl: Unable to parse usbdevice.\n");
            exit(-ERROR_FAIL);
        }
        xlu_cfg_replace_string (config, "soundhw", &b_info->u.hvm.soundhw, 0);
        xlu_cfg_get_defbool(config, "xen_platform_pci",
                            &b_info->u.hvm.xen_platform_pci, 0);

        if(b_info->u.hvm.vnc.listen
           && b_info->u.hvm.vnc.display
           && strchr(b_info->u.hvm.vnc.listen, ':') != NULL) {
            fprintf(stderr,
                    "ERROR: Display specified both in vnclisten"
                    " and vncdisplay!\n");
            exit (1);

        }

        if (!xlu_cfg_get_string (config, "vendor_device", &buf, 0)) {
            libxl_vendor_device d;

            e = libxl_vendor_device_from_string(buf, &d);
            if (e) {
                fprintf(stderr,
                        "xl: unknown vendor_device '%s'\n",
                        buf);
                exit(-ERROR_FAIL);
            }

            b_info->u.hvm.vendor_device = d;
        }
    }

    xlu_cfg_destroy(config);
}

static void reload_domain_config(uint32_t domid,
                                 libxl_domain_config *d_config)
{
    int rc;
    uint8_t *t_data;
    int ret, t_len;
    libxl_domain_config d_config_new;

    /* In case user has used "config-update" to store a new config
     * file.
     */
    ret = libxl_userdata_retrieve(ctx, domid, "xl", &t_data, &t_len);
    if (ret && errno != ENOENT) {
        LOG("\"xl\" configuration found but failed to load\n");
    }
    if (t_len > 0) {
        LOG("\"xl\" configuration found, using it\n");
        libxl_domain_config_dispose(d_config);
        parse_config_data("<updated>", (const char *)t_data,
                          t_len, d_config);
        free(t_data);
        libxl_userdata_unlink(ctx, domid, "xl");
        return;
    }

    libxl_domain_config_init(&d_config_new);
    rc = libxl_retrieve_domain_configuration(ctx, domid, &d_config_new);
    if (rc) {
        LOG("failed to retrieve guest configuration (rc=%d). "
            "reusing old configuration", rc);
        libxl_domain_config_dispose(&d_config_new);
    } else {
        libxl_domain_config_dispose(d_config);
        /* Steal allocations */
        memcpy(d_config, &d_config_new, sizeof(libxl_domain_config));
    }
}

/* Returns 1 if domain should be restarted,
 * 2 if domain should be renamed then restarted, or 0
 * Can update r_domid if domain is destroyed etc */
static int handle_domain_death(uint32_t *r_domid,
                               libxl_event *event,
                               libxl_domain_config *d_config)

{
    int restart = 0;
    libxl_action_on_shutdown action;

    switch (event->u.domain_shutdown.shutdown_reason) {
    case LIBXL_SHUTDOWN_REASON_POWEROFF:
        action = d_config->on_poweroff;
        break;
    case LIBXL_SHUTDOWN_REASON_REBOOT:
        action = d_config->on_reboot;
        break;
    case LIBXL_SHUTDOWN_REASON_SUSPEND:
        LOG("Domain has suspended.");
        return 0;
    case LIBXL_SHUTDOWN_REASON_CRASH:
        action = d_config->on_crash;
        break;
    case LIBXL_SHUTDOWN_REASON_WATCHDOG:
        action = d_config->on_watchdog;
        break;
    default:
        LOG("Unknown shutdown reason code %d. Destroying domain.",
            event->u.domain_shutdown.shutdown_reason);
        action = LIBXL_ACTION_ON_SHUTDOWN_DESTROY;
    }

    LOG("Action for shutdown reason code %d is %s",
        event->u.domain_shutdown.shutdown_reason,
        action_on_shutdown_names[action]);

    if (action == LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_DESTROY || action == LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_RESTART) {
        char *corefile;
        int rc;

        if (asprintf(&corefile, "/var/xen/dump/%s", d_config->c_info.name) < 0) {
            LOG("failed to construct core dump path");
        } else {
            LOG("dumping core to %s", corefile);
            rc=libxl_domain_core_dump(ctx, *r_domid, corefile, NULL);
            if (rc) LOG("core dump failed (rc=%d).", rc);
            free(corefile);
        }
        /* No point crying over spilled milk, continue on failure. */

        if (action == LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_DESTROY)
            action = LIBXL_ACTION_ON_SHUTDOWN_DESTROY;
        else
            action = LIBXL_ACTION_ON_SHUTDOWN_RESTART;
    }

    switch (action) {
    case LIBXL_ACTION_ON_SHUTDOWN_PRESERVE:
        break;

    case LIBXL_ACTION_ON_SHUTDOWN_RESTART_RENAME:
        reload_domain_config(*r_domid, d_config);
        restart = 2;
        break;

    case LIBXL_ACTION_ON_SHUTDOWN_RESTART:
        reload_domain_config(*r_domid, d_config);
        restart = 1;
        /* fall-through */
    case LIBXL_ACTION_ON_SHUTDOWN_DESTROY:
        LOG("Domain %d needs to be cleaned up: destroying the domain",
            *r_domid);
        libxl_domain_destroy(ctx, *r_domid, 0);
        *r_domid = INVALID_DOMID;
        break;

    case LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_DESTROY:
    case LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_RESTART:
        /* Already handled these above. */
        abort();
    }

    return restart;
}

/* for now used only by main_networkattach, but can be reused elsewhere */
static int match_option_size(const char *prefix, size_t len,
        char *arg, char **argopt)
{
    int rc = strncmp(prefix, arg, len);
    if (!rc) *argopt = arg+len;
    return !rc;
}
#define MATCH_OPTION(prefix, arg, oparg) \
    match_option_size((prefix "="), sizeof((prefix)), (arg), &(oparg))

/* Preserve a copy of a domain under a new name. Updates *r_domid */
static int preserve_domain(uint32_t *r_domid, libxl_event *event,
                           libxl_domain_config *d_config)
{
    time_t now;
    struct tm tm;
    char strtime[24];

    libxl_uuid new_uuid;

    int rc;

    now = time(NULL);
    if (now == ((time_t) -1)) {
        LOG("Failed to get current time for domain rename");
        return 0;
    }

    tzset();
    if (gmtime_r(&now, &tm) == NULL) {
        LOG("Failed to convert time to UTC");
        return 0;
    }

    if (!strftime(&strtime[0], sizeof(strtime), "-%Y%m%dT%H%MZ", &tm)) {
        LOG("Failed to format time as a string");
        return 0;
    }

    libxl_uuid_generate(&new_uuid);

    LOG("Preserving domain %d %s with suffix%s",
        *r_domid, d_config->c_info.name, strtime);
    rc = libxl_domain_preserve(ctx, *r_domid, &d_config->c_info,
                               strtime, new_uuid);

    /*
     * Although the domain still exists it is no longer the one we are
     * concerned with.
     */
    *r_domid = INVALID_DOMID;

    return rc == 0 ? 1 : 0;
}

static int freemem(uint32_t domid, libxl_domain_build_info *b_info)
{
    int rc, retries = 3;
    uint32_t need_memkb, free_memkb;

    if (!autoballoon)
        return 0;

    rc = libxl_domain_need_memory(ctx, b_info, &need_memkb);
    if (rc < 0)
        return rc;

    do {
        rc = libxl_get_free_memory(ctx, &free_memkb);
        if (rc < 0)
            return rc;

        if (free_memkb >= need_memkb)
            return 0;

        rc = libxl_set_memory_target(ctx, 0, free_memkb - need_memkb, 1, 0);
        if (rc < 0)
            return rc;

        rc = libxl_wait_for_free_memory(ctx, domid, need_memkb, 10);
        if (!rc)
            return 0;
        else if (rc != ERROR_NOMEM)
            return rc;

        /* the memory target has been reached but the free memory is still
         * not enough: loop over again */
        rc = libxl_wait_for_memory_target(ctx, 0, 1);
        if (rc < 0)
            return rc;

        retries--;
    } while (retries > 0);

    return ERROR_NOMEM;
}

static void autoconnect_console(libxl_ctx *ctx_ignored,
                                libxl_event *ev, void *priv)
{
    uint32_t bldomid = ev->domid;

    libxl_event_free(ctx, ev);

    console_child_report(child_console);

    pid_t pid = xl_fork(child_console, "console child");
    if (pid)
        return;

    postfork();

    sleep(1);
    libxl_primary_console_exec(ctx, bldomid);
    /* Do not return. xl continued in child process */
    perror("xl: unable to exec console client");
    _exit(1);
}

static int domain_wait_event(uint32_t domid, libxl_event **event_r)
{
    int ret;
    for (;;) {
        ret = libxl_event_wait(ctx, event_r, LIBXL_EVENTMASK_ALL, 0,0);
        if (ret) {
            LOG("Domain %d, failed to get event, quitting (rc=%d)", domid, ret);
            return ret;
        }
        if ((*event_r)->domid != domid) {
            char *evstr = libxl_event_to_json(ctx, *event_r);
            LOG("INTERNAL PROBLEM - ignoring unexpected event for"
                " domain %d (expected %d): event=%s",
                (*event_r)->domid, domid, evstr);
            free(evstr);
            libxl_event_free(ctx, *event_r);
            continue;
        }
        return ret;
    }
}

static void evdisable_disk_ejects(libxl_evgen_disk_eject **diskws,
                                 int num_disks)
{
    int i;

    for (i = 0; i < num_disks; i++) {
        if (diskws[i])
            libxl_evdisable_disk_eject(ctx, diskws[i]);
        diskws[i] = NULL;
    }
}

static uint32_t create_domain(struct domain_create *dom_info)
{
    uint32_t domid = INVALID_DOMID;

    libxl_domain_config d_config;

    int debug = dom_info->debug;
    int daemonize = dom_info->daemonize;
    int monitor = dom_info->monitor;
    int paused = dom_info->paused;
    int vncautopass = dom_info->vncautopass;
    const char *config_file = dom_info->config_file;
    const char *extra_config = dom_info->extra_config;
    const char *restore_file = dom_info->restore_file;
    const char *config_source = NULL;
    const char *restore_source = NULL;
    int migrate_fd = dom_info->migrate_fd;
    bool config_in_json;

    int i;
    int need_daemon = daemonize;
    int ret, rc;
    libxl_evgen_domain_death *deathw = NULL;
    libxl_evgen_disk_eject **diskws = NULL; /* one per disk */
    void *config_data = 0;
    int config_len = 0;
    int restore_fd = -1;
    const libxl_asyncprogress_how *autoconnect_console_how;
    struct save_file_header hdr;

    int restoring = (restore_file || (migrate_fd >= 0));

    libxl_domain_config_init(&d_config);

    if (restoring) {
        uint8_t *optdata_begin = 0;
        const uint8_t *optdata_here = 0;
        union { uint32_t u32; char b[4]; } u32buf;
        uint32_t badflags;

        if (migrate_fd >= 0) {
            restore_source = "<incoming migration stream>";
            restore_fd = migrate_fd;
        } else {
            restore_source = restore_file;
            restore_fd = open(restore_file, O_RDONLY);
            if (restore_fd == -1) {
                fprintf(stderr, "Can't open restore file: %s\n", strerror(errno));
                return ERROR_INVAL;
            }
            rc = libxl_fd_set_cloexec(ctx, restore_fd, 1);
            if (rc) return rc;
        }

        CHK_ERRNOVAL(libxl_read_exactly(
                         ctx, restore_fd, &hdr, sizeof(hdr),
                         restore_source, "header"));
        if (memcmp(hdr.magic, savefileheader_magic, sizeof(hdr.magic))) {
            fprintf(stderr, "File has wrong magic number -"
                    " corrupt or for a different tool?\n");
            return ERROR_INVAL;
        }
        if (hdr.byteorder != SAVEFILE_BYTEORDER_VALUE) {
            fprintf(stderr, "File has wrong byte order\n");
            return ERROR_INVAL;
        }
        fprintf(stderr, "Loading new save file %s"
                " (new xl fmt info"
                " 0x%"PRIx32"/0x%"PRIx32"/%"PRIu32")\n",
                restore_source, hdr.mandatory_flags, hdr.optional_flags,
                hdr.optional_data_len);

        badflags = hdr.mandatory_flags & ~XL_MANDATORY_FLAG_ALL;
        if (badflags) {
            fprintf(stderr, "Savefile has mandatory flag(s) 0x%"PRIx32" "
                    "which are not supported; need newer xl\n",
                    badflags);
            return ERROR_INVAL;
        }
        if (hdr.optional_data_len) {
            optdata_begin = xmalloc(hdr.optional_data_len);
            CHK_ERRNOVAL(libxl_read_exactly(
                             ctx, restore_fd, optdata_begin,
                             hdr.optional_data_len, restore_source,
                             "optdata"));
        }

#define OPTDATA_LEFT  (hdr.optional_data_len - (optdata_here - optdata_begin))
#define WITH_OPTDATA(amt, body)                                 \
            if (OPTDATA_LEFT < (amt)) {                         \
                fprintf(stderr, "Savefile truncated.\n");       \
                return ERROR_INVAL;                             \
            } else {                                            \
                body;                                           \
                optdata_here += (amt);                          \
            }

        optdata_here = optdata_begin;

        if (OPTDATA_LEFT) {
            fprintf(stderr, " Savefile contains xl domain config%s\n",
                    !!(hdr.mandatory_flags & XL_MANDATORY_FLAG_JSON)
                    ? " in JSON format" : "");
            WITH_OPTDATA(4, {
                memcpy(u32buf.b, optdata_here, 4);
                config_len = u32buf.u32;
            });
            WITH_OPTDATA(config_len, {
                config_data = xmalloc(config_len);
                memcpy(config_data, optdata_here, config_len);
            });
        }

    }

    if (config_file) {
        free(config_data);  config_data = 0;
        /* /dev/null represents special case (read config. from command line) */
        if (!strcmp(config_file, "/dev/null")) {
            config_len = 0;
        } else {
            ret = libxl_read_file_contents(ctx, config_file,
                                           &config_data, &config_len);
            if (ret) { fprintf(stderr, "Failed to read config file: %s: %s\n",
                               config_file, strerror(errno)); return ERROR_FAIL; }
        }
        if (!restoring && extra_config && strlen(extra_config)) {
            if (config_len > INT_MAX - (strlen(extra_config) + 2 + 1)) {
                fprintf(stderr, "Failed to attach extra configration\n");
                return ERROR_FAIL;
            }
            /* allocate space for the extra config plus two EOLs plus \0 */
            config_data = realloc(config_data, config_len
                + strlen(extra_config) + 2 + 1);
            if (!config_data) {
                fprintf(stderr, "Failed to realloc config_data\n");
                return ERROR_FAIL;
            }
            config_len += sprintf(config_data + config_len, "\n%s\n",
                extra_config);
        }
        config_source=config_file;
        config_in_json = false;
    } else {
        if (!config_data) {
            fprintf(stderr, "Config file not specified and"
                    " none in save file\n");
            return ERROR_INVAL;
        }
        config_source = "<saved>";
        config_in_json = !!(hdr.mandatory_flags & XL_MANDATORY_FLAG_JSON);
    }

    if (!dom_info->quiet)
        fprintf(stderr, "Parsing config from %s\n", config_source);

    if (config_in_json) {
        libxl_domain_config_from_json(ctx, &d_config,
                                      (const char *)config_data);
    } else {
        parse_config_data(config_source, config_data, config_len, &d_config);
    }

    if (migrate_fd >= 0) {
        if (d_config.c_info.name) {
            /* when we receive a domain we get its name from the config
             * file; and we receive it to a temporary name */
            assert(!common_domname);

            common_domname = d_config.c_info.name;
            d_config.c_info.name = 0; /* steals allocation from config */

            if (asprintf(&d_config.c_info.name,
                         "%s--incoming", common_domname) < 0) {
                fprintf(stderr, "Failed to allocate memory in asprintf\n");
                exit(1);
            }
            *dom_info->migration_domname_r = strdup(d_config.c_info.name);
        }
    }

    if (debug || dom_info->dryrun)
        printf_info(default_output_format, -1, &d_config,
                    debug ? stderr : stdout);

    ret = 0;
    if (dom_info->dryrun)
        goto out;

start:
    assert(domid == INVALID_DOMID);

    rc = acquire_lock();
    if (rc < 0)
        goto error_out;

    ret = freemem(domid, &d_config.b_info);
    if (ret < 0) {
        fprintf(stderr, "failed to free memory for the domain\n");
        ret = ERROR_FAIL;
        goto error_out;
    }

    libxl_asyncprogress_how autoconnect_console_how_buf;
    if ( dom_info->console_autoconnect ) {
        autoconnect_console_how_buf.callback = autoconnect_console;
        autoconnect_console_how = &autoconnect_console_how_buf;
    }else{
        autoconnect_console_how = 0;
    }

    if ( restoring ) {
        libxl_domain_restore_params params;

        libxl_domain_restore_params_init(&params);

        params.checkpointed_stream = dom_info->checkpointed_stream;
        ret = libxl_domain_create_restore(ctx, &d_config,
                                          &domid, restore_fd,
                                          &params,
                                          0, autoconnect_console_how);

        libxl_domain_restore_params_dispose(&params);

        /*
         * On subsequent reboot etc we should create the domain, not
         * restore/migrate-receive it again.
         */
        restoring = 0;
    }else{
        ret = libxl_domain_create_new(ctx, &d_config, &domid,
                                      0, autoconnect_console_how);
    }
    if ( ret )
        goto error_out;

    release_lock();

    if (!paused)
        libxl_domain_unpause(ctx, domid);

    ret = domid; /* caller gets success in parent */
    if (!daemonize && !monitor)
        goto out;

    if (dom_info->vnc)
        autoconnect_vncviewer(domid, vncautopass);

    if (need_daemon) {
        char *name;

        if (asprintf(&name, "xl-%s", d_config.c_info.name) < 0) {
            LOG("Failed to allocate memory in asprintf");
            exit(1);
        }
        ret = do_daemonize(name);
        free(name);
        if (ret) {
            ret = (ret == 1) ? domid : ret;
            goto out;
        }
        need_daemon = 0;
    }
    LOG("Waiting for domain %s (domid %d) to die [pid %ld]",
        d_config.c_info.name, domid, (long)getpid());

    ret = libxl_evenable_domain_death(ctx, domid, 0, &deathw);
    if (ret) goto out;

    if (!diskws) {
        diskws = xmalloc(sizeof(*diskws) * d_config.num_disks);
        for (i = 0; i < d_config.num_disks; i++)
            diskws[i] = NULL;
    }
    for (i = 0; i < d_config.num_disks; i++) {
        if (d_config.disks[i].removable) {
            ret = libxl_evenable_disk_eject(ctx, domid, d_config.disks[i].vdev,
                                            0, &diskws[i]);
            if (ret) goto out;
        }
    }
    while (1) {
        libxl_event *event;
        ret = domain_wait_event(domid, &event);
        if (ret) goto out;

        switch (event->type) {

        case LIBXL_EVENT_TYPE_DOMAIN_SHUTDOWN:
            LOG("Domain %d has shut down, reason code %d 0x%x", domid,
                event->u.domain_shutdown.shutdown_reason,
                event->u.domain_shutdown.shutdown_reason);
            switch (handle_domain_death(&domid, event, &d_config)) {
            case 2:
                if (!preserve_domain(&domid, event, &d_config)) {
                    /* If we fail then exit leaving the old domain in place. */
                    ret = -1;
                    goto out;
                }

                /* Otherwise fall through and restart. */
            case 1:
                libxl_event_free(ctx, event);
                libxl_evdisable_domain_death(ctx, deathw);
                deathw = NULL;
                evdisable_disk_ejects(diskws, d_config.num_disks);
                /* discard any other events which may have been generated */
                while (!(ret = libxl_event_check(ctx, &event,
                                                 LIBXL_EVENTMASK_ALL, 0,0))) {
                    libxl_event_free(ctx, event);
                }
                if (ret != ERROR_NOT_READY) {
                    LOG("warning, libxl_event_check (cleanup) failed (rc=%d)",
                        ret);
                }

                /*
                 * Do not attempt to reconnect if we come round again due to a
                 * guest reboot -- the stdin/out will be disconnected by then.
                 */
                dom_info->console_autoconnect = 0;

                /* Some settings only make sense on first boot. */
                paused = 0;
                if (common_domname
                    && strcmp(d_config.c_info.name, common_domname)) {
                    d_config.c_info.name = strdup(common_domname);
                }

                /*
                 * XXX FIXME: If this sleep is not there then domain
                 * re-creation fails sometimes.
                 */
                LOG("Done. Rebooting now");
                sleep(2);
                goto start;

            case 0:
                LOG("Done. Exiting now");
                libxl_event_free(ctx, event);
                ret = 0;
                goto out;

            default:
                abort();
            }

        case LIBXL_EVENT_TYPE_DOMAIN_DEATH:
            LOG("Domain %d has been destroyed.", domid);
            libxl_event_free(ctx, event);
            ret = 0;
            goto out;

        case LIBXL_EVENT_TYPE_DISK_EJECT:
            /* XXX what is this for? */
            libxl_cdrom_insert(ctx, domid, &event->u.disk_eject.disk, NULL);
            break;

        default:;
            char *evstr = libxl_event_to_json(ctx, event);
            LOG("warning, got unexpected event type %d, event=%s",
                event->type, evstr);
            free(evstr);
        }

        libxl_event_free(ctx, event);
    }

error_out:
    release_lock();
    if (libxl_domid_valid_guest(domid)) {
        libxl_domain_destroy(ctx, domid, 0);
        domid = INVALID_DOMID;
    }

out:
    if (logfile != 2)
        close(logfile);

    libxl_domain_config_dispose(&d_config);

    free(config_data);

    console_child_report(child_console);

    if (deathw)
        libxl_evdisable_domain_death(ctx, deathw);
    if (diskws) {
        evdisable_disk_ejects(diskws, d_config.num_disks);
        free(diskws);
    }

    /*
     * If we have daemonized then do not return to the caller -- this has
     * already happened in the parent.
     */
    if ( daemonize && !need_daemon )
        exit(ret);

    return ret;
}

void help(const char *command)
{
    int i;
    struct cmd_spec *cmd;

    if (!command || !strcmp(command, "help")) {
        printf("Usage xl [-vfN] <subcommand> [args]\n\n");
        printf("xl full list of subcommands:\n\n");
        for (i = 0; i < cmdtable_len; i++) {
            printf(" %-19s ", cmd_table[i].cmd_name);
            if (strlen(cmd_table[i].cmd_name) > 19)
                printf("\n %-19s ", "");
            printf("%s\n", cmd_table[i].cmd_desc);
        }
    } else {
        cmd = cmdtable_lookup(command);
        if (cmd) {
            printf("Usage: xl [-v%s%s] %s %s\n\n%s.\n\n",
                   cmd->modifies ? "f" : "",
                   cmd->can_dryrun ? "N" : "",
                   cmd->cmd_name,
                   cmd->cmd_usage,
                   cmd->cmd_desc);
            if (cmd->cmd_option)
                printf("Options:\n\n%s\n", cmd->cmd_option);
        }
        else {
            printf("command \"%s\" not implemented\n", command);
        }
    }
}

static int64_t parse_mem_size_kb(const char *mem)
{
    char *endptr;
    int64_t kbytes;

    kbytes = strtoll(mem, &endptr, 10);

    if (strlen(endptr) > 1)
        return -1;

    switch (tolower((uint8_t)*endptr)) {
    case 't':
        kbytes <<= 10;
    case 'g':
        kbytes <<= 10;
    case '\0':
    case 'm':
        kbytes <<= 10;
    case 'k':
        break;
    case 'b':
        kbytes >>= 10;
        break;
    default:
        return -1;
    }

    return kbytes;
}

#define COMMON_LONG_OPTS {"help", 0, 0, 'h'}

/*
 * Callers should use SWITCH_FOREACH_OPT in preference to calling this
 * directly.
 */
static int def_getopt(int argc, char * const argv[],
                      const char *optstring,
                      const struct option *longopts,
                      const char* helpstr, int reqargs)
{
    int opt;
    const struct option def_options[] = {
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    if (!longopts)
        longopts = def_options;

    opterr = 0;
    while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) == '?') {
        if (optopt == 'h') {
            help(helpstr);
            exit(0);
        }
        fprintf(stderr, "option `%c' not supported.\n", optopt);
    }
    if (opt == 'h') {
        help(helpstr);
        exit(0);
    }
    if (opt != -1)
        return opt;

    if (argc - optind <= reqargs - 1) {
        fprintf(stderr, "'xl %s' requires at least %d argument%s.\n\n",
                helpstr, reqargs, reqargs > 1 ? "s" : "");
        help(helpstr);
        exit(2);
    }
    return -1;
}

/*
 * Wraps def_getopt into a convenient loop+switch to process all
 * arguments. This macro is intended to be called from main_XXX().
 *
 *   SWITCH_FOREACH_OPT(int *opt, const char *opts,
 *                      const struct option *longopts,
 *                      const char *commandname,
 *                      int num_opts_req) { ...
 *
 * opt:               pointer to an int variable, holds the current option
 *                    during processing.
 * opts:              short options, as per getopt_long(3)'s optstring argument.
 * longopts:          long options, as per getopt_long(3)'s longopts argument.
 *                    May be null.
 * commandname:       name of this command, for usage string.
 * num_required_opts: number of non-option command line parameters
 *                    which are required.
 *
 * In addition the calling context is expected to contain variables
 * "argc" and "argv" in the conventional C-style:
 *   main(int argc, char **argv)
 * manner.
 *
 * Callers should treat SWITCH_FOREACH_OPT as they would a switch
 * statement over the value of `opt`. Each option given in `opts` (or
 * `lopts`) should be handled by a case statement as if it were inside
 * a switch statement.
 *
 * In addition to the options provided in opts the macro will handle
 * the "help" option and enforce a minimum number of non-option
 * command line pearameters as follows:
 *  -- if the user passes a -h or --help option. help will be printed,
 *     and the macro will cause the process to exit with code 0.
 *  -- if the user does not provided `num_required_opts` non-option
 *     arguments, the macro will cause the process to exit with code 2.
 *
 * Example:
 *
 * int main_foo(int argc, char **argv) {
 *     int opt;
 *
 *     SWITCH_FOREACH_OPT(opt, "blah", NULL, "foo", 0) {
 *      case 'b':
 *          ... handle b option...
 *          break;
 *      case 'l':
 *          ... handle l option ...
 *          break;
 *      case etc etc...
 *      }
 *      ... do something useful with the options ...
 * }
 */
#define SWITCH_FOREACH_OPT(opt, opts, longopts,                         \
                           commandname, num_required_opts)              \
    while (((opt) = def_getopt(argc, argv, (opts), (longopts),          \
                                (commandname), (num_required_opts))) != -1) \
        switch (opt)

static int set_memory_max(uint32_t domid, const char *mem)
{
    int64_t memorykb;
    int rc;

    memorykb = parse_mem_size_kb(mem);
    if (memorykb == -1) {
        fprintf(stderr, "invalid memory size: %s\n", mem);
        exit(3);
    }

    rc = libxl_domain_setmaxmem(ctx, domid, memorykb);

    return rc;
}

int main_memmax(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0;
    char *mem;
    int rc;

    SWITCH_FOREACH_OPT(opt, "", NULL, "mem-max", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    mem = argv[optind + 1];

    rc = set_memory_max(domid, mem);
    if (rc) {
        fprintf(stderr, "cannot set domid %d static max memory to : %s\n", domid, mem);
        return 1;
    }

    return 0;
}

static void set_memory_target(uint32_t domid, const char *mem)
{
    long long int memorykb;

    memorykb = parse_mem_size_kb(mem);
    if (memorykb == -1)  {
        fprintf(stderr, "invalid memory size: %s\n", mem);
        exit(3);
    }

    libxl_set_memory_target(ctx, domid, memorykb, 0, /* enforce */ 1);
}

int main_memset(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0;
    const char *mem;

    SWITCH_FOREACH_OPT(opt, "", NULL, "mem-set", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    mem = argv[optind + 1];

    set_memory_target(domid, mem);
    return 0;
}

static int cd_insert(uint32_t domid, const char *virtdev, char *phys)
{
    libxl_device_disk disk;
    char *buf = NULL;
    XLU_Config *config = 0;
    struct stat b;
    int rc = 0;

    if (asprintf(&buf, "vdev=%s,access=r,devtype=cdrom,target=%s",
                 virtdev, phys ? phys : "") < 0) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }

    parse_disk_config(&config, buf, &disk);

    /* ATM the existence of the backing file is not checked for qdisk
     * in libxl_cdrom_insert() because RAW is used for remote
     * protocols as well as plain files.  This will ideally be changed
     * for 4.4, but this work-around fixes the problem of "cd-insert"
     * returning success for non-existent files. */
    if (disk.format != LIBXL_DISK_FORMAT_EMPTY
        && stat(disk.pdev_path, &b)) {
        fprintf(stderr, "Cannot stat file: %s\n",
                disk.pdev_path);
        rc = 1;
        goto out;
    }

    if (libxl_cdrom_insert(ctx, domid, &disk, NULL))
        rc=1;

out:
    libxl_device_disk_dispose(&disk);
    free(buf);

    return rc;
}

int main_cd_eject(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0;
    const char *virtdev;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cd-eject", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    virtdev = argv[optind + 1];

    return cd_insert(domid, virtdev, NULL);
}

int main_cd_insert(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0;
    const char *virtdev;
    char *file = NULL; /* modified by cd_insert tokenising it */

    SWITCH_FOREACH_OPT(opt, "", NULL, "cd-insert", 3) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    virtdev = argv[optind + 1];
    file = argv[optind + 2];

    cd_insert(domid, virtdev, file);
    return 0;
}

int main_console(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0, num = 0;
    libxl_console_type type = 0;

    SWITCH_FOREACH_OPT(opt, "n:t:", NULL, "console", 1) {
    case 't':
        if (!strcmp(optarg, "pv"))
            type = LIBXL_CONSOLE_TYPE_PV;
        else if (!strcmp(optarg, "serial"))
            type = LIBXL_CONSOLE_TYPE_SERIAL;
        else {
            fprintf(stderr, "console type supported are: pv, serial\n");
            return 2;
        }
        break;
    case 'n':
        num = atoi(optarg);
        break;
    }

    domid = find_domain(argv[optind]);
    if (!type)
        libxl_primary_console_exec(ctx, domid);
    else
        libxl_console_exec(ctx, domid, num, type);
    fprintf(stderr, "Unable to attach console\n");
    return 1;
}

int main_vncviewer(int argc, char **argv)
{
    static const struct option opts[] = {
        {"autopass", 0, 0, 'a'},
        {"vncviewer-autopass", 0, 0, 'a'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };
    uint32_t domid;
    int opt, autopass = 0;

    SWITCH_FOREACH_OPT(opt, "ah", opts, "vncviewer", 1) {
    case 'a':
        autopass = 1;
        break;
    }

    domid = find_domain(argv[optind]);

    if (vncviewer(domid, autopass))
        return 1;
    return 0;
}

static void pcilist(uint32_t domid)
{
    libxl_device_pci *pcidevs;
    int num, i;

    pcidevs = libxl_device_pci_list(ctx, domid, &num);
    if (pcidevs == NULL)
        return;
    printf("Vdev Device\n");
    for (i = 0; i < num; i++) {
        printf("%02x.%01x %04x:%02x:%02x.%01x\n",
               (pcidevs[i].vdevfn >> 3) & 0x1f, pcidevs[i].vdevfn & 0x7,
               pcidevs[i].domain, pcidevs[i].bus, pcidevs[i].dev, pcidevs[i].func);
        libxl_device_pci_dispose(&pcidevs[i]);
    }
    free(pcidevs);
}

int main_pcilist(int argc, char **argv)
{
    uint32_t domid;
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pci-list", 1) {
        /* No options */
    }

    domid = find_domain(argv[optind]);

    pcilist(domid);
    return 0;
}

static void pcidetach(uint32_t domid, const char *bdf, int force)
{
    libxl_device_pci pcidev;
    XLU_Config *config;

    libxl_device_pci_init(&pcidev);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_inig"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pcidev, bdf)) {
        fprintf(stderr, "pci-detach: malformed BDF specification \"%s\"\n", bdf);
        exit(2);
    }
    if (force)
        libxl_device_pci_destroy(ctx, domid, &pcidev, 0);
    else
        libxl_device_pci_remove(ctx, domid, &pcidev, 0);

    libxl_device_pci_dispose(&pcidev);
    xlu_cfg_destroy(config);
}

int main_pcidetach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    int force = 0;
    const char *bdf = NULL;

    SWITCH_FOREACH_OPT(opt, "f", NULL, "pci-detach", 2) {
    case 'f':
        force = 1;
        break;
    }

    domid = find_domain(argv[optind]);
    bdf = argv[optind + 1];

    pcidetach(domid, bdf, force);
    return 0;
}
static void pciattach(uint32_t domid, const char *bdf, const char *vs)
{
    libxl_device_pci pcidev;
    XLU_Config *config;

    libxl_device_pci_init(&pcidev);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_inig"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pcidev, bdf)) {
        fprintf(stderr, "pci-attach: malformed BDF specification \"%s\"\n", bdf);
        exit(2);
    }
    libxl_device_pci_add(ctx, domid, &pcidev, 0);

    libxl_device_pci_dispose(&pcidev);
    xlu_cfg_destroy(config);
}

int main_pciattach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    const char *bdf = NULL, *vs = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pci-attach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    bdf = argv[optind + 1];

    if (optind + 1 < argc)
        vs = argv[optind + 2];

    pciattach(domid, bdf, vs);
    return 0;
}

static void pciassignable_list(void)
{
    libxl_device_pci *pcidevs;
    int num, i;

    pcidevs = libxl_device_pci_assignable_list(ctx, &num);

    if ( pcidevs == NULL )
        return;
    for (i = 0; i < num; i++) {
        printf("%04x:%02x:%02x.%01x\n",
               pcidevs[i].domain, pcidevs[i].bus, pcidevs[i].dev, pcidevs[i].func);
        libxl_device_pci_dispose(&pcidevs[i]);
    }
    free(pcidevs);
}

int main_pciassignable_list(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pci-assignable-list", 0) {
        /* No options */
    }

    pciassignable_list();
    return 0;
}

static void pciassignable_add(const char *bdf, int rebind)
{
    libxl_device_pci pcidev;
    XLU_Config *config;

    libxl_device_pci_init(&pcidev);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_init"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pcidev, bdf)) {
        fprintf(stderr, "pci-assignable-add: malformed BDF specification \"%s\"\n", bdf);
        exit(2);
    }
    libxl_device_pci_assignable_add(ctx, &pcidev, rebind);

    libxl_device_pci_dispose(&pcidev);
    xlu_cfg_destroy(config);
}

int main_pciassignable_add(int argc, char **argv)
{
    int opt;
    const char *bdf = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pci-assignable-add", 1) {
        /* No options */
    }

    bdf = argv[optind];

    pciassignable_add(bdf, 1);
    return 0;
}

static void pciassignable_remove(const char *bdf, int rebind)
{
    libxl_device_pci pcidev;
    XLU_Config *config;

    libxl_device_pci_init(&pcidev);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_init"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pcidev, bdf)) {
        fprintf(stderr, "pci-assignable-remove: malformed BDF specification \"%s\"\n", bdf);
        exit(2);
    }
    libxl_device_pci_assignable_remove(ctx, &pcidev, rebind);

    libxl_device_pci_dispose(&pcidev);
    xlu_cfg_destroy(config);
}

int main_pciassignable_remove(int argc, char **argv)
{
    int opt;
    const char *bdf = NULL;
    int rebind = 0;

    SWITCH_FOREACH_OPT(opt, "r", NULL, "pci-assignable-remove", 1) {
    case 'r':
        rebind=1;
        break;
    }

    bdf = argv[optind];

    pciassignable_remove(bdf, rebind);
    return 0;
}

static void pause_domain(uint32_t domid)
{
    libxl_domain_pause(ctx, domid);
}

static void unpause_domain(uint32_t domid)
{
    libxl_domain_unpause(ctx, domid);
}

static void destroy_domain(uint32_t domid, int force)
{
    int rc;

    if (domid == 0 && !force) {
        fprintf(stderr, "Not destroying domain 0; use -f to force.\n"
                        "This can only be done when using a disaggregated "
                        "hardware domain and toolstack.\n\n");
        exit(-1);
    }
    rc = libxl_domain_destroy(ctx, domid, 0);
    if (rc) { fprintf(stderr,"destroy failed (rc=%d)\n",rc); exit(-1); }
}

static void wait_for_domain_deaths(libxl_evgen_domain_death **deathws, int nr)
{
    int rc, count = 0;
    LOG("Waiting for %d domains", nr);
    while(1 && count < nr) {
        libxl_event *event;
        rc = libxl_event_wait(ctx, &event, LIBXL_EVENTMASK_ALL, 0,0);
        if (rc) {
            LOG("Failed to get event, quitting (rc=%d)", rc);
            exit(-1);
        }

        switch (event->type) {
        case LIBXL_EVENT_TYPE_DOMAIN_DEATH:
            LOG("Domain %d has been destroyed", event->domid);
            libxl_evdisable_domain_death(ctx, deathws[event->for_user]);
            count++;
            break;
        case LIBXL_EVENT_TYPE_DOMAIN_SHUTDOWN:
            LOG("Domain %d has been shut down, reason code %d",
                event->domid, event->u.domain_shutdown.shutdown_reason);
            libxl_evdisable_domain_death(ctx, deathws[event->for_user]);
            count++;
            break;
        default:
            LOG("Unexpected event type %d", event->type);
            break;
        }
        libxl_event_free(ctx, event);
    }
}

static void shutdown_domain(uint32_t domid,
                            libxl_evgen_domain_death **deathw,
                            libxl_ev_user for_user,
                            int fallback_trigger)
{
    int rc;

    fprintf(stderr, "Shutting down domain %d\n", domid);
    rc=libxl_domain_shutdown(ctx, domid);
    if (rc == ERROR_NOPARAVIRT) {
        if (fallback_trigger) {
            fprintf(stderr, "PV control interface not available:"
                    " sending ACPI power button event.\n");
            rc = libxl_send_trigger(ctx, domid, LIBXL_TRIGGER_POWER, 0);
        } else {
            fprintf(stderr, "PV control interface not available:"
                    " external graceful shutdown not possible.\n");
            fprintf(stderr, "Use \"-F\" to fallback to ACPI power event.\n");
        }
    }

    if (rc) {
        fprintf(stderr,"shutdown failed (rc=%d)\n",rc);exit(-1);
    }

    if (deathw) {
        rc = libxl_evenable_domain_death(ctx, domid, for_user, deathw);
        if (rc) {
            fprintf(stderr,"wait for death failed (evgen, rc=%d)\n",rc);
            exit(-1);
        }
    }
}

static void reboot_domain(uint32_t domid, libxl_evgen_domain_death **deathw,
                          libxl_ev_user for_user, int fallback_trigger)
{
    int rc;

    fprintf(stderr, "Rebooting domain %d\n", domid);
    rc=libxl_domain_reboot(ctx, domid);
    if (rc == ERROR_NOPARAVIRT) {
        if (fallback_trigger) {
            fprintf(stderr, "PV control interface not available:"
                    " sending ACPI reset button event.\n");
            rc = libxl_send_trigger(ctx, domid, LIBXL_TRIGGER_RESET, 0);
        } else {
            fprintf(stderr, "PV control interface not available:"
                    " external graceful reboot not possible.\n");
            fprintf(stderr, "Use \"-F\" to fallback to ACPI reset event.\n");
        }
    }
    if (rc) {
        fprintf(stderr,"reboot failed (rc=%d)\n",rc);exit(-1);
    }

    if (deathw) {
        rc = libxl_evenable_domain_death(ctx, domid, for_user, deathw);
        if (rc) {
            fprintf(stderr,"wait for death failed (evgen, rc=%d)\n",rc);
            exit(-1);
        }
    }
}

static void list_domains_details(const libxl_dominfo *info, int nb_domain)
{
    libxl_domain_config d_config;

    int i, rc;

    yajl_gen hand = NULL;
    yajl_gen_status s;
    const char *buf;
    libxl_yajl_length yajl_len = 0;

    if (default_output_format == OUTPUT_FORMAT_JSON) {
        hand = libxl_yajl_gen_alloc(NULL);
        if (!hand) {
            fprintf(stderr, "unable to allocate JSON generator\n");
            return;
        }

        s = yajl_gen_array_open(hand);
        if (s != yajl_gen_status_ok)
            goto out;
    } else
        s = yajl_gen_status_ok;

    for (i = 0; i < nb_domain; i++) {
        libxl_domain_config_init(&d_config);
        rc = libxl_retrieve_domain_configuration(ctx, info[i].domid, &d_config);
        if (rc)
            continue;
        if (default_output_format == OUTPUT_FORMAT_JSON)
            s = printf_info_one_json(hand, info[i].domid, &d_config);
        else
            printf_info_sexp(info[i].domid, &d_config, stdout);
        libxl_domain_config_dispose(&d_config);
        if (s != yajl_gen_status_ok)
            goto out;
    }

    if (default_output_format == OUTPUT_FORMAT_JSON) {
        s = yajl_gen_array_close(hand);
        if (s != yajl_gen_status_ok)
            goto out;

        s = yajl_gen_get_buf(hand, (const unsigned char **)&buf, &yajl_len);
        if (s != yajl_gen_status_ok)
            goto out;

        puts(buf);
    }

out:
    if (default_output_format == OUTPUT_FORMAT_JSON) {
        yajl_gen_free(hand);
        if (s != yajl_gen_status_ok)
            fprintf(stderr,
                    "unable to format domain config as JSON (YAJL:%d)\n", s);
    }
}

static void print_bitmap(uint8_t *map, int maplen, FILE *stream)
{
    int i;
    uint8_t pmap = 0, bitmask = 0;
    int firstset = 0, state = 0;

    for (i = 0; i < maplen; i++) {
        if (i % 8 == 0) {
            pmap = *map++;
            bitmask = 1;
        } else bitmask <<= 1;

        switch (state) {
        case 0:
        case 2:
            if ((pmap & bitmask) != 0) {
                firstset = i;
                state++;
            }
            continue;
        case 1:
        case 3:
            if ((pmap & bitmask) == 0) {
                fprintf(stream, "%s%d", state > 1 ? "," : "", firstset);
                if (i - 1 > firstset)
                    fprintf(stream, "-%d", i - 1);
                state = 2;
            }
            continue;
        }
    }
    switch (state) {
        case 0:
            fprintf(stream, "none");
            break;
        case 2:
            break;
        case 1:
            if (firstset == 0) {
                fprintf(stream, "all");
                break;
            }
        case 3:
            fprintf(stream, "%s%d", state > 1 ? "," : "", firstset);
            if (i - 1 > firstset)
                fprintf(stream, "-%d", i - 1);
            break;
    }
}

static void list_domains(int verbose, int context, int claim, int numa,
                         const libxl_dominfo *info, int nb_domain)
{
    int i;
    static const char shutdown_reason_letters[]= "-rscw";
    libxl_bitmap nodemap;
    libxl_physinfo physinfo;

    libxl_bitmap_init(&nodemap);
    libxl_physinfo_init(&physinfo);

    printf("Name                                        ID   Mem VCPUs\tState\tTime(s)");
    if (verbose) printf("   UUID                            Reason-Code\tSecurity Label");
    if (context && !verbose) printf("   Security Label");
    if (claim) printf("  Claimed");
    if (numa) {
        if (libxl_node_bitmap_alloc(ctx, &nodemap, 0)) {
            fprintf(stderr, "libxl_node_bitmap_alloc_failed.\n");
            exit(1);
        }
        if (libxl_get_physinfo(ctx, &physinfo) != 0) {
            fprintf(stderr, "libxl_physinfo failed.\n");
            libxl_bitmap_dispose(&nodemap);
            exit(1);
        }

        printf(" NODE Affinity");
    }
    printf("\n");
    for (i = 0; i < nb_domain; i++) {
        char *domname;
        unsigned shutdown_reason;
        domname = libxl_domid_to_name(ctx, info[i].domid);
        shutdown_reason = info[i].shutdown ? info[i].shutdown_reason : 0;
        printf("%-40s %5d %5lu %5d     %c%c%c%c%c%c  %8.1f",
                domname,
                info[i].domid,
                (unsigned long) ((info[i].current_memkb +
                    info[i].outstanding_memkb)/ 1024),
                info[i].vcpu_online,
                info[i].running ? 'r' : '-',
                info[i].blocked ? 'b' : '-',
                info[i].paused ? 'p' : '-',
                info[i].shutdown ? 's' : '-',
                (shutdown_reason >= 0 &&
                 shutdown_reason < sizeof(shutdown_reason_letters)-1
                 ? shutdown_reason_letters[shutdown_reason] : '?'),
                info[i].dying ? 'd' : '-',
                ((float)info[i].cpu_time / 1e9));
        free(domname);
        if (verbose) {
            printf(" " LIBXL_UUID_FMT, LIBXL_UUID_BYTES(info[i].uuid));
            if (info[i].shutdown) printf(" %8x", shutdown_reason);
            else printf(" %8s", "-");
        }
        if (claim)
            printf(" %5lu", (unsigned long)info[i].outstanding_memkb / 1024);
        if (verbose || context)
            printf(" %16s", info[i].ssid_label ? : "-");
        if (numa) {
            libxl_domain_get_nodeaffinity(ctx, info[i].domid, &nodemap);

            putchar(' ');
            print_bitmap(nodemap.map, physinfo.nr_nodes, stdout);
        }
        putchar('\n');
    }

    libxl_bitmap_dispose(&nodemap);
    libxl_physinfo_dispose(&physinfo);
}

static void list_vm(void)
{
    libxl_vminfo *info;
    char *domname;
    int nb_vm, i;

    info = libxl_list_vm(ctx, &nb_vm);

    if (!info) {
        fprintf(stderr, "libxl_list_vm failed.\n");
        exit(1);
    }
    printf("UUID                                  ID    name\n");
    for (i = 0; i < nb_vm; i++) {
        domname = libxl_domid_to_name(ctx, info[i].domid);
        printf(LIBXL_UUID_FMT "  %d    %-30s\n", LIBXL_UUID_BYTES(info[i].uuid),
            info[i].domid, domname);
        free(domname);
    }
    libxl_vminfo_list_free(info, nb_vm);
}

static void core_dump_domain(uint32_t domid, const char *filename)
{
    int rc;

    rc=libxl_domain_core_dump(ctx, domid, filename, NULL);
    if (rc) { fprintf(stderr,"core dump failed (rc=%d)\n",rc);exit(-1); }
}

#ifndef LIBXL_HAVE_NO_SUSPEND_RESUME
static void save_domain_core_begin(uint32_t domid,
                                   const char *override_config_file,
                                   uint8_t **config_data_r,
                                   int *config_len_r)
{
    int rc;
    libxl_domain_config d_config;
    char *config_c = 0;

    /* configuration file in optional data: */

    libxl_domain_config_init(&d_config);

    if (override_config_file) {
        void *config_v = 0;
        rc = libxl_read_file_contents(ctx, override_config_file,
                                      &config_v, config_len_r);
        if (rc) {
            fprintf(stderr, "unable to read overridden config file\n");
            exit(2);
        }
        parse_config_data(override_config_file, config_v, *config_len_r,
                          &d_config);
        free(config_v);
    } else {
        rc = libxl_retrieve_domain_configuration(ctx, domid, &d_config);
        if (rc) {
            fprintf(stderr, "unable to retrieve domain configuration\n");
            exit(2);
        }
    }

    config_c = libxl_domain_config_to_json(ctx, &d_config);
    if (!config_c) {
        fprintf(stderr, "unable to convert config file to JSON\n");
        exit(2);
    }
    *config_data_r = (uint8_t *)config_c;
    *config_len_r = strlen(config_c) + 1; /* including trailing '\0' */

    libxl_domain_config_dispose(&d_config);
}

static void save_domain_core_writeconfig(int fd, const char *source,
                                  const uint8_t *config_data, int config_len)
{
    struct save_file_header hdr;
    uint8_t *optdata_begin;
    union { uint32_t u32; char b[4]; } u32buf;

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, savefileheader_magic, sizeof(hdr.magic));
    hdr.byteorder = SAVEFILE_BYTEORDER_VALUE;

    optdata_begin= 0;

#define ADD_OPTDATA(ptr, len) ({                                            \
    if ((len)) {                                                        \
        hdr.optional_data_len += (len);                                 \
        optdata_begin = xrealloc(optdata_begin, hdr.optional_data_len); \
        memcpy(optdata_begin + hdr.optional_data_len - (len),           \
               (ptr), (len));                                           \
    }                                                                   \
                          })

    u32buf.u32 = config_len;
    ADD_OPTDATA(u32buf.b,    4);
    ADD_OPTDATA(config_data, config_len);
    if (config_len)
        hdr.mandatory_flags |= XL_MANDATORY_FLAG_JSON;

    /* that's the optional data */

    CHK_ERRNOVAL(libxl_write_exactly(
                     ctx, fd, &hdr, sizeof(hdr), source, "header"));
    CHK_ERRNOVAL(libxl_write_exactly(
                     ctx, fd, optdata_begin, hdr.optional_data_len,
                     source, "header"));

    free(optdata_begin);

    fprintf(stderr, "Saving to %s new xl format (info"
            " 0x%"PRIx32"/0x%"PRIx32"/%"PRIu32")\n",
            source, hdr.mandatory_flags, hdr.optional_flags,
            hdr.optional_data_len);
}

static int save_domain(uint32_t domid, const char *filename, int checkpoint,
                            int leavepaused, const char *override_config_file)
{
    int fd;
    uint8_t *config_data;
    int config_len;

    save_domain_core_begin(domid, override_config_file,
                           &config_data, &config_len);

    if (!config_len) {
        fputs(" Savefile will not contain xl domain config\n", stderr);
    }

    fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "Failed to open temp file %s for writing\n", filename);
        exit(2);
    }

    save_domain_core_writeconfig(fd, filename, config_data, config_len);

    int rc = libxl_domain_suspend(ctx, domid, fd, 0, NULL);
    close(fd);

    if (rc < 0) {
        fprintf(stderr, "Failed to save domain, resuming domain\n");
        libxl_domain_resume(ctx, domid, 1, 0);
    }
    else if (leavepaused || checkpoint) {
        if (leavepaused)
            libxl_domain_pause(ctx, domid);
        libxl_domain_resume(ctx, domid, 1, 0);
    }
    else
        libxl_domain_destroy(ctx, domid, 0);

    exit(rc < 0 ? 1 : 0);
}

static pid_t create_migration_child(const char *rune, int *send_fd,
                                        int *recv_fd)
{
    int sendpipe[2], recvpipe[2];
    pid_t child = -1;

    if (!rune || !send_fd || !recv_fd)
        return -1;

    MUST( libxl_pipe(ctx, sendpipe) );
    MUST( libxl_pipe(ctx, recvpipe) );

    child = xl_fork(child_migration, "migration transport process");

    if (!child) {
        dup2(sendpipe[0], 0);
        dup2(recvpipe[1], 1);
        close(sendpipe[0]); close(sendpipe[1]);
        close(recvpipe[0]); close(recvpipe[1]);
        execlp("sh","sh","-c",rune,(char*)0);
        perror("failed to exec sh");
        exit(-1);
    }

    close(sendpipe[0]);
    close(recvpipe[1]);
    *send_fd = sendpipe[1];
    *recv_fd = recvpipe[0];

    /* if receiver dies, we get an error and can clean up
       rather than just dying */
    signal(SIGPIPE, SIG_IGN);

    return child;
}

static int migrate_read_fixedmessage(int fd, const void *msg, int msgsz,
                                     const char *what, const char *rune) {
    char buf[msgsz];
    const char *stream;
    int rc;

    stream = rune ? "migration receiver stream" : "migration stream";
    rc = libxl_read_exactly(ctx, fd, buf, msgsz, stream, what);
    if (rc) return ERROR_FAIL;

    if (memcmp(buf, msg, msgsz)) {
        fprintf(stderr, "%s contained unexpected data instead of %s\n",
                stream, what);
        if (rune)
            fprintf(stderr, "(command run was: %s )\n", rune);
        return ERROR_FAIL;
    }
    return 0;
}

static void migration_child_report(int recv_fd) {
    pid_t child;
    int status, sr;
    struct timeval now, waituntil, timeout;
    static const struct timeval pollinterval = { 0, 1000 }; /* 1ms */

    if (!xl_child_pid(child_migration)) return;

    CHK_SYSCALL(gettimeofday(&waituntil, 0));
    waituntil.tv_sec += 2;

    for (;;) {
        pid_t migration_child = xl_child_pid(child_migration);
        child = xl_waitpid(child_migration, &status, WNOHANG);

        if (child == migration_child) {
            if (status)
                xl_report_child_exitstatus(XTL_INFO, child_migration,
                                           migration_child, status);
            break;
        }
        if (child == -1) {
            fprintf(stderr, "wait for migration child [%ld] failed: %s\n",
                    (long)migration_child, strerror(errno));
            break;
        }
        assert(child == 0);

        CHK_SYSCALL(gettimeofday(&now, 0));
        if (timercmp(&now, &waituntil, >)) {
            fprintf(stderr, "migration child [%ld] not exiting, no longer"
                    " waiting (exit status will be unreported)\n",
                    (long)migration_child);
            break;
        }
        timersub(&waituntil, &now, &timeout);

        if (recv_fd >= 0) {
            fd_set readfds, exceptfds;
            FD_ZERO(&readfds);
            FD_ZERO(&exceptfds);
            FD_SET(recv_fd, &readfds);
            FD_SET(recv_fd, &exceptfds);
            sr = select(recv_fd+1, &readfds,0,&exceptfds, &timeout);
        } else {
            if (timercmp(&timeout, &pollinterval, >))
                timeout = pollinterval;
            sr = select(0,0,0,0, &timeout);
        }
        if (sr > 0) {
            recv_fd = -1;
        } else if (sr == 0) {
        } else if (sr == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "migration child [%ld] exit wait select"
                        " failed unexpectedly: %s\n",
                        (long)migration_child, strerror(errno));
                break;
            }
        }
    }
}

static void migrate_do_preamble(int send_fd, int recv_fd, pid_t child,
                                uint8_t *config_data, int config_len,
                                const char *rune)
{
    int rc = 0;

    if (send_fd < 0 || recv_fd < 0) {
        fprintf(stderr, "migrate_do_preamble: invalid file descriptors\n");
        exit(1);
    }

    rc = migrate_read_fixedmessage(recv_fd, migrate_receiver_banner,
                                   sizeof(migrate_receiver_banner)-1,
                                   "banner", rune);
    if (rc) {
        close(send_fd);
        migration_child_report(recv_fd);
        exit(-rc);
    }

    save_domain_core_writeconfig(send_fd, "migration stream",
                                 config_data, config_len);

}

static void migrate_domain(uint32_t domid, const char *rune, int debug,
                           const char *override_config_file)
{
    pid_t child = -1;
    int rc;
    int send_fd = -1, recv_fd = -1;
    char *away_domname;
    char rc_buf;
    uint8_t *config_data;
    int config_len, flags = LIBXL_SUSPEND_LIVE;

    save_domain_core_begin(domid, override_config_file,
                           &config_data, &config_len);

    if (!config_len) {
        fprintf(stderr, "No config file stored for running domain and "
                "none supplied - cannot migrate.\n");
        exit(1);
    }

    child = create_migration_child(rune, &send_fd, &recv_fd);

    migrate_do_preamble(send_fd, recv_fd, child, config_data, config_len,
                        rune);

    xtl_stdiostream_adjust_flags(logger, XTL_STDIOSTREAM_HIDE_PROGRESS, 0);

    if (debug)
        flags |= LIBXL_SUSPEND_DEBUG;
    rc = libxl_domain_suspend(ctx, domid, send_fd, flags, NULL);
    if (rc) {
        fprintf(stderr, "migration sender: libxl_domain_suspend failed"
                " (rc=%d)\n", rc);
        if (rc == ERROR_GUEST_TIMEDOUT)
            goto failed_suspend;
        else
            goto failed_resume;
    }

    //fprintf(stderr, "migration sender: Transfer complete.\n");
    // Should only be printed when debugging as it's a bit messy with
    // progress indication.

    rc = migrate_read_fixedmessage(recv_fd, migrate_receiver_ready,
                                   sizeof(migrate_receiver_ready),
                                   "ready message", rune);
    if (rc) goto failed_resume;

    xtl_stdiostream_adjust_flags(logger, 0, XTL_STDIOSTREAM_HIDE_PROGRESS);

    /* right, at this point we are about give the destination
     * permission to rename and resume, so we must first rename the
     * domain away ourselves */

    fprintf(stderr, "migration sender: Target has acknowledged transfer.\n");

    if (common_domname) {
        if (asprintf(&away_domname, "%s--migratedaway", common_domname) < 0)
            goto failed_resume;
        rc = libxl_domain_rename(ctx, domid, common_domname, away_domname);
        if (rc) goto failed_resume;
    }

    /* point of no return - as soon as we have tried to say
     * "go" to the receiver, it's not safe to carry on.  We leave
     * the domain renamed to %s--migratedaway in case that's helpful.
     */

    fprintf(stderr, "migration sender: Giving target permission to start.\n");

    rc = libxl_write_exactly(ctx, send_fd,
                             migrate_permission_to_go,
                             sizeof(migrate_permission_to_go),
                             "migration stream", "GO message");
    if (rc) goto failed_badly;

    rc = migrate_read_fixedmessage(recv_fd, migrate_report,
                                   sizeof(migrate_report),
                                   "success/failure report message", rune);
    if (rc) goto failed_badly;

    rc = libxl_read_exactly(ctx, recv_fd,
                            &rc_buf, 1,
                            "migration ack stream", "success/failure status");
    if (rc) goto failed_badly;

    if (rc_buf) {
        fprintf(stderr, "migration sender: Target reports startup failure"
                " (status code %d).\n", rc_buf);

        rc = migrate_read_fixedmessage(recv_fd, migrate_permission_to_go,
                                       sizeof(migrate_permission_to_go),
                                       "permission for sender to resume",
                                       rune);
        if (rc) goto failed_badly;

        fprintf(stderr, "migration sender: Trying to resume at our end.\n");

        if (common_domname) {
            libxl_domain_rename(ctx, domid, away_domname, common_domname);
        }
        rc = libxl_domain_resume(ctx, domid, 1, 0);
        if (!rc) fprintf(stderr, "migration sender: Resumed OK.\n");

        fprintf(stderr, "Migration failed due to problems at target.\n");
        exit(-ERROR_FAIL);
    }

    fprintf(stderr, "migration sender: Target reports successful startup.\n");
    libxl_domain_destroy(ctx, domid, 0); /* bang! */
    fprintf(stderr, "Migration successful.\n");
    exit(0);

 failed_suspend:
    close(send_fd);
    migration_child_report(recv_fd);
    fprintf(stderr, "Migration failed, failed to suspend at sender.\n");
    exit(-ERROR_FAIL);

 failed_resume:
    close(send_fd);
    migration_child_report(recv_fd);
    fprintf(stderr, "Migration failed, resuming at sender.\n");
    libxl_domain_resume(ctx, domid, 1, 0);
    exit(-ERROR_FAIL);

 failed_badly:
    fprintf(stderr,
 "** Migration failed during final handshake **\n"
 "Domain state is now undefined !\n"
 "Please CHECK AT BOTH ENDS for running instances, before renaming and\n"
 " resuming at most one instance.  Two simultaneous instances of the domain\n"
 " would probably result in SEVERE DATA LOSS and it is now your\n"
 " responsibility to avoid that.  Sorry.\n");

    close(send_fd);
    migration_child_report(recv_fd);
    exit(-ERROR_BADFAIL);
}

static void migrate_receive(int debug, int daemonize, int monitor,
                            int send_fd, int recv_fd, int remus)
{
    uint32_t domid;
    int rc, rc2;
    char rc_buf;
    char *migration_domname;
    struct domain_create dom_info;

    signal(SIGPIPE, SIG_IGN);
    /* if we get SIGPIPE we'd rather just have it as an error */

    fprintf(stderr, "migration target: Ready to receive domain.\n");

    CHK_ERRNOVAL(libxl_write_exactly(
                     ctx, send_fd, migrate_receiver_banner,
                     sizeof(migrate_receiver_banner)-1,
                     "migration ack stream", "banner") );

    memset(&dom_info, 0, sizeof(dom_info));
    dom_info.debug = debug;
    dom_info.daemonize = daemonize;
    dom_info.monitor = monitor;
    dom_info.paused = 1;
    dom_info.migrate_fd = recv_fd;
    dom_info.migration_domname_r = &migration_domname;
    dom_info.checkpointed_stream = remus;

    rc = create_domain(&dom_info);
    if (rc < 0) {
        fprintf(stderr, "migration target: Domain creation failed"
                " (code %d).\n", rc);
        exit(-rc);
    }

    domid = rc;

    if (remus) {
        /* If we are here, it means that the sender (primary) has crashed.
         * TODO: Split-Brain Check.
         */
        fprintf(stderr, "migration target: Remus Failover for domain %u\n",
                domid);

        /*
         * If domain renaming fails, lets just continue (as we need the domain
         * to be up & dom names may not matter much, as long as its reachable
         * over network).
         *
         * If domain unpausing fails, destroy domain ? Or is it better to have
         * a consistent copy of the domain (memory, cpu state, disk)
         * on atleast one physical host ? Right now, lets just leave the domain
         * as is and let the Administrator decide (or troubleshoot).
         */
        if (migration_domname) {
            rc = libxl_domain_rename(ctx, domid, migration_domname,
                                     common_domname);
            if (rc)
                fprintf(stderr, "migration target (Remus): "
                        "Failed to rename domain from %s to %s:%d\n",
                        migration_domname, common_domname, rc);
        }

        rc = libxl_domain_unpause(ctx, domid);
        if (rc)
            fprintf(stderr, "migration target (Remus): "
                    "Failed to unpause domain %s (id: %u):%d\n",
                    common_domname, domid, rc);

        exit(rc ? -ERROR_FAIL: 0);
    }

    fprintf(stderr, "migration target: Transfer complete,"
            " requesting permission to start domain.\n");

    rc = libxl_write_exactly(ctx, send_fd,
                             migrate_receiver_ready,
                             sizeof(migrate_receiver_ready),
                             "migration ack stream", "ready message");
    if (rc) exit(-rc);

    rc = migrate_read_fixedmessage(recv_fd, migrate_permission_to_go,
                                   sizeof(migrate_permission_to_go),
                                   "GO message", 0);
    if (rc) goto perhaps_destroy_notify_rc;

    fprintf(stderr, "migration target: Got permission, starting domain.\n");

    if (migration_domname) {
        rc = libxl_domain_rename(ctx, domid, migration_domname, common_domname);
        if (rc) goto perhaps_destroy_notify_rc;
    }

    rc = libxl_domain_unpause(ctx, domid);
    if (rc) goto perhaps_destroy_notify_rc;

    fprintf(stderr, "migration target: Domain started successsfully.\n");
    rc = 0;

 perhaps_destroy_notify_rc:
    rc2 = libxl_write_exactly(ctx, send_fd,
                              migrate_report, sizeof(migrate_report),
                              "migration ack stream",
                              "success/failure report");
    if (rc2) exit(-ERROR_BADFAIL);

    rc_buf = -rc;
    assert(!!rc_buf == !!rc);
    rc2 = libxl_write_exactly(ctx, send_fd, &rc_buf, 1,
                              "migration ack stream",
                              "success/failure code");
    if (rc2) exit(-ERROR_BADFAIL);

    if (rc) {
        fprintf(stderr, "migration target: Failure, destroying our copy.\n");

        rc2 = libxl_domain_destroy(ctx, domid, 0);
        if (rc2) {
            fprintf(stderr, "migration target: Failed to destroy our copy"
                    " (code %d).\n", rc2);
            exit(-ERROR_BADFAIL);
        }

        fprintf(stderr, "migration target: Cleanup OK, granting sender"
                " permission to resume.\n");

        rc2 = libxl_write_exactly(ctx, send_fd,
                                  migrate_permission_to_go,
                                  sizeof(migrate_permission_to_go),
                                  "migration ack stream",
                                  "permission to sender to have domain back");
        if (rc2) exit(-ERROR_BADFAIL);
    }

    exit(0);
}

int main_restore(int argc, char **argv)
{
    const char *checkpoint_file = NULL;
    const char *config_file = NULL;
    struct domain_create dom_info;
    int paused = 0, debug = 0, daemonize = 1, monitor = 1,
        console_autoconnect = 0, vnc = 0, vncautopass = 0;
    int opt, rc;
    static struct option opts[] = {
        {"vncviewer", 0, 0, 'V'},
        {"vncviewer-autopass", 0, 0, 'A'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    SWITCH_FOREACH_OPT(opt, "FhcpdeVA", opts, "restore", 1) {
    case 'c':
        console_autoconnect = 1;
        break;
    case 'p':
        paused = 1;
        break;
    case 'd':
        debug = 1;
        break;
    case 'F':
        daemonize = 0;
        break;
    case 'e':
        daemonize = 0;
        monitor = 0;
        break;
    case 'V':
        vnc = 1;
        break;
    case 'A':
        vnc = vncautopass = 1;
        break;
    }

    if (argc-optind == 1) {
        checkpoint_file = argv[optind];
    } else if (argc-optind == 2) {
        config_file = argv[optind];
        checkpoint_file = argv[optind + 1];
    } else {
        help("restore");
        return 2;
    }

    memset(&dom_info, 0, sizeof(dom_info));
    dom_info.debug = debug;
    dom_info.daemonize = daemonize;
    dom_info.monitor = monitor;
    dom_info.paused = paused;
    dom_info.config_file = config_file;
    dom_info.restore_file = checkpoint_file;
    dom_info.migrate_fd = -1;
    dom_info.vnc = vnc;
    dom_info.vncautopass = vncautopass;
    dom_info.console_autoconnect = console_autoconnect;

    rc = create_domain(&dom_info);
    if (rc < 0)
        return -rc;

    return 0;
}

int main_migrate_receive(int argc, char **argv)
{
    int debug = 0, daemonize = 1, monitor = 1, remus = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "Fedr", NULL, "migrate-receive", 0) {
    case 'F':
        daemonize = 0;
        break;
    case 'e':
        daemonize = 0;
        monitor = 0;
        break;
    case 'd':
        debug = 1;
        break;
    case 'r':
        remus = 1;
        break;
    }

    if (argc-optind != 0) {
        help("migrate-receive");
        return 2;
    }
    migrate_receive(debug, daemonize, monitor,
                    STDOUT_FILENO, STDIN_FILENO,
                    remus);

    return 0;
}

int main_save(int argc, char **argv)
{
    uint32_t domid;
    const char *filename;
    const char *config_filename = NULL;
    int checkpoint = 0;
    int leavepaused = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "cp", NULL, "save", 2) {
    case 'c':
        checkpoint = 1;
        break;
    case 'p':
        leavepaused = 1;
        break;
    }

    if (argc-optind > 3) {
        help("save");
        return 2;
    }

    domid = find_domain(argv[optind]);
    filename = argv[optind + 1];
    if ( argc - optind >= 3 )
        config_filename = argv[optind + 2];

    save_domain(domid, filename, checkpoint, leavepaused, config_filename);
    return 0;
}

int main_migrate(int argc, char **argv)
{
    uint32_t domid;
    const char *config_filename = NULL;
    const char *ssh_command = "ssh";
    char *rune = NULL;
    char *host;
    int opt, daemonize = 1, monitor = 1, debug = 0;
    static struct option opts[] = {
        {"debug", 0, 0, 0x100},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    SWITCH_FOREACH_OPT(opt, "FC:s:e", opts, "migrate", 2) {
    case 'C':
        config_filename = optarg;
        break;
    case 's':
        ssh_command = optarg;
        break;
    case 'F':
        daemonize = 0;
        break;
    case 'e':
        daemonize = 0;
        monitor = 0;
        break;
    case 0x100:
        debug = 1;
        break;
    }

    domid = find_domain(argv[optind]);
    host = argv[optind + 1];

    bool pass_tty_arg = progress_use_cr || (isatty(2) > 0);

    if (!ssh_command[0]) {
        rune= host;
    } else {
        char verbose_buf[minmsglevel_default+3];
        int verbose_len;
        verbose_buf[0] = ' ';
        verbose_buf[1] = '-';
        memset(verbose_buf+2, 'v', minmsglevel_default);
        verbose_buf[sizeof(verbose_buf)-1] = 0;
        if (minmsglevel == minmsglevel_default) {
            verbose_len = 0;
        } else {
            verbose_len = (minmsglevel_default - minmsglevel) + 2;
        }
        if (asprintf(&rune, "exec %s %s xl%s%.*s migrate-receive%s%s",
                     ssh_command, host,
                     pass_tty_arg ? " -t" : "",
                     verbose_len, verbose_buf,
                     daemonize ? "" : " -e",
                     debug ? " -d" : "") < 0)
            return 1;
    }

    migrate_domain(domid, rune, debug, config_filename);
    return 0;
}
#endif

int main_dump_core(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "dump-core", 2) {
        /* No options */
    }

    core_dump_domain(find_domain(argv[optind]), argv[optind + 1]);
    return 0;
}

int main_pause(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pause", 1) {
        /* No options */
    }

    pause_domain(find_domain(argv[optind]));

    return 0;
}

int main_unpause(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "unpause", 1) {
        /* No options */
    }

    unpause_domain(find_domain(argv[optind]));

    return 0;
}

int main_destroy(int argc, char **argv)
{
    int opt;
    int force = 0;

    SWITCH_FOREACH_OPT(opt, "f", NULL, "destroy", 1) {
    case 'f':
        force = 1;
        break;
    }

    destroy_domain(find_domain(argv[optind]), force);
    return 0;
}

static int main_shutdown_or_reboot(int do_reboot, int argc, char **argv)
{
    const char *what = do_reboot ? "reboot" : "shutdown";
    void (*fn)(uint32_t domid,
               libxl_evgen_domain_death **, libxl_ev_user, int) =
        do_reboot ? &reboot_domain : &shutdown_domain;
    int opt, i, nb_domain;
    int wait_for_it = 0, all =0;
    int fallback_trigger = 0;
    static struct option opts[] = {
        {"all", 0, 0, 'a'},
        {"wait", 0, 0, 'w'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    SWITCH_FOREACH_OPT(opt, "awF", opts, what, 0) {
    case 'a':
        all = 1;
        break;
    case 'w':
        wait_for_it = 1;
        break;
    case 'F':
        fallback_trigger = 1;
        break;
    }

    if (!argv[optind] && !all) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        return opt;
    }

    if (all) {
        libxl_dominfo *dominfo;
        libxl_evgen_domain_death **deathws = NULL;
        if (!(dominfo = libxl_list_domain(ctx, &nb_domain))) {
            fprintf(stderr, "libxl_list_domain failed.\n");
            return -1;
        }

        if (wait_for_it)
            deathws = calloc(nb_domain, sizeof(*deathws));

        for (i = 0; i<nb_domain; i++) {
            if (dominfo[i].domid == 0)
                continue;
            fn(dominfo[i].domid, deathws ? &deathws[i] : NULL, i,
               fallback_trigger);
        }

        if (wait_for_it)
            wait_for_domain_deaths(deathws, nb_domain - 1 /* not dom 0 */);

        libxl_dominfo_list_free(dominfo, nb_domain);
    } else {
        libxl_evgen_domain_death *deathw = NULL;
        uint32_t domid = find_domain(argv[optind]);

        fn(domid, wait_for_it ? &deathw : NULL, 0, fallback_trigger);

        if (wait_for_it)
            wait_for_domain_deaths(&deathw, 1);
    }


    return 0;
}

int main_shutdown(int argc, char **argv)
{
    return main_shutdown_or_reboot(0, argc, argv);
}

int main_reboot(int argc, char **argv)
{
    return main_shutdown_or_reboot(1, argc, argv);
}

int main_list(int argc, char **argv)
{
    int opt, verbose = 0;
    int context = 0;
    int details = 0;
    int numa = 0;
    static struct option opts[] = {
        {"long", 0, 0, 'l'},
        {"verbose", 0, 0, 'v'},
        {"context", 0, 0, 'Z'},
        {"numa", 0, 0, 'n'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    libxl_dominfo info_buf;
    libxl_dominfo *info, *info_free=0;
    int nb_domain, rc;

    SWITCH_FOREACH_OPT(opt, "lvhZn", opts, "list", 0) {
    case 'l':
        details = 1;
        break;
    case 'v':
        verbose = 1;
        break;
    case 'Z':
        context = 1;
        break;
    case 'n':
        numa = 1;
        break;
    }

    if (optind >= argc) {
        info = libxl_list_domain(ctx, &nb_domain);
        if (!info) {
            fprintf(stderr, "libxl_list_domain failed.\n");
            return 1;
        }
        info_free = info;
    } else if (optind == argc-1) {
        uint32_t domid = find_domain(argv[optind]);
        rc = libxl_domain_info(ctx, &info_buf, domid);
        if (rc == ERROR_INVAL) {
            fprintf(stderr, "Error: Domain \'%s\' does not exist.\n",
                argv[optind]);
            return -rc;
        }
        if (rc) {
            fprintf(stderr, "libxl_domain_info failed (code %d).\n", rc);
            return -rc;
        }
        info = &info_buf;
        nb_domain = 1;
    } else {
        help("list");
        return 2;
    }

    if (details)
        list_domains_details(info, nb_domain);
    else
        list_domains(verbose, context, 0 /* claim */, numa, info, nb_domain);

    if (info_free)
        libxl_dominfo_list_free(info, nb_domain);
    else
        libxl_dominfo_dispose(info);

    return 0;
}

int main_vm_list(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vm-list", 0) {
        /* No options */
    }

    list_vm();
    return 0;
}

int main_create(int argc, char **argv)
{
    const char *filename = NULL;
    char *p;
    char extra_config[1024];
    struct domain_create dom_info;
    int paused = 0, debug = 0, daemonize = 1, console_autoconnect = 0,
        quiet = 0, monitor = 1, vnc = 0, vncautopass = 0;
    int opt, rc;
    static struct option opts[] = {
        {"dryrun", 0, 0, 'n'},
        {"quiet", 0, 0, 'q'},
        {"defconfig", 1, 0, 'f'},
        {"vncviewer", 0, 0, 'V'},
        {"vncviewer-autopass", 0, 0, 'A'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    if (argv[1] && argv[1][0] != '-' && !strchr(argv[1], '=')) {
        filename = argv[1];
        argc--; argv++;
    }

    SWITCH_FOREACH_OPT(opt, "Fhnqf:pcdeVA", opts, "create", 0) {
    case 'f':
        filename = optarg;
        break;
    case 'p':
        paused = 1;
        break;
    case 'c':
        console_autoconnect = 1;
        break;
    case 'd':
        debug = 1;
        break;
    case 'F':
        daemonize = 0;
        break;
    case 'e':
        daemonize = 0;
        monitor = 0;
        break;
    case 'n':
        dryrun_only = 1;
        break;
    case 'q':
        quiet = 1;
        break;
    case 'V':
        vnc = 1;
        break;
    case 'A':
        vnc = vncautopass = 1;
        break;
    }

    extra_config[0] = '\0';
    for (p = extra_config; optind < argc; optind++) {
        if (strchr(argv[optind], '=') != NULL) {
            p += snprintf(p, sizeof(extra_config) - (p - extra_config),
                "%s\n", argv[optind]);
        } else if (!filename) {
            filename = argv[optind];
        } else {
            help("create");
            return 2;
        }
    }

    memset(&dom_info, 0, sizeof(dom_info));
    dom_info.debug = debug;
    dom_info.daemonize = daemonize;
    dom_info.monitor = monitor;
    dom_info.paused = paused;
    dom_info.dryrun = dryrun_only;
    dom_info.quiet = quiet;
    dom_info.config_file = filename;
    dom_info.extra_config = extra_config;
    dom_info.migrate_fd = -1;
    dom_info.vnc = vnc;
    dom_info.vncautopass = vncautopass;
    dom_info.console_autoconnect = console_autoconnect;

    rc = create_domain(&dom_info);
    if (rc < 0)
        return -rc;

    return 0;
}

int main_config_update(int argc, char **argv)
{
    uint32_t domid;
    const char *filename = NULL;
    char *p;
    char extra_config[1024];
    void *config_data = 0;
    int config_len = 0;
    libxl_domain_config d_config;
    int opt, rc;
    int debug = 0;
    static struct option opts[] = {
        {"defconfig", 1, 0, 'f'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    if (argc < 2) {
        fprintf(stderr, "xl config-update requires a domain argument\n");
        help("config-update");
        exit(1);
    }

    fprintf(stderr, "WARNING: xl now has better capability to manage domain configuration, "
            "avoid using this command when possible\n");

    domid = find_domain(argv[1]);
    argc--; argv++;

    if (argv[1] && argv[1][0] != '-' && !strchr(argv[1], '=')) {
        filename = argv[1];
        argc--; argv++;
    }

    SWITCH_FOREACH_OPT(opt, "dhqf:", opts, "config_update", 0) {
    case 'd':
        debug = 1;
        break;
    case 'f':
        filename = optarg;
        break;
    }

    extra_config[0] = '\0';
    for (p = extra_config; optind < argc; optind++) {
        if (strchr(argv[optind], '=') != NULL) {
            p += snprintf(p, sizeof(extra_config) - (p - extra_config),
                "%s\n", argv[optind]);
        } else if (!filename) {
            filename = argv[optind];
        } else {
            help("create");
            return 2;
        }
    }
    if (filename) {
        free(config_data);  config_data = 0;
        rc = libxl_read_file_contents(ctx, filename,
                                      &config_data, &config_len);
        if (rc) { fprintf(stderr, "Failed to read config file: %s: %s\n",
                           filename, strerror(errno)); return ERROR_FAIL; }
        if (strlen(extra_config)) {
            if (config_len > INT_MAX - (strlen(extra_config) + 2 + 1)) {
                fprintf(stderr, "Failed to attach extra configration\n");
                exit(1);
            }
            /* allocate space for the extra config plus two EOLs plus \0 */
            config_data = realloc(config_data, config_len
                + strlen(extra_config) + 2 + 1);
            if (!config_data) {
                fprintf(stderr, "Failed to realloc config_data\n");
                exit(1);
            }
            config_len += sprintf(config_data + config_len, "\n%s\n",
                extra_config);
        }
    } else {
        fprintf(stderr, "Config file not specified\n");
        exit(1);
    }

    libxl_domain_config_init(&d_config);

    parse_config_data(filename, config_data, config_len, &d_config);

    if (debug || dryrun_only)
        printf_info(default_output_format, -1, &d_config, stdout);

    if (!dryrun_only) {
        fprintf(stderr, "setting dom%d configuration\n", domid);
        rc = libxl_userdata_store(ctx, domid, "xl",
                                   config_data, config_len);
        if (rc) {
            fprintf(stderr, "failed to update configuration\n");
            exit(1);
        }
    }

    libxl_domain_config_dispose(&d_config);

    free(config_data);

    return 0;
}

static void button_press(uint32_t domid, const char *b)
{
    libxl_trigger trigger;

    if (!strcmp(b, "power")) {
        trigger = LIBXL_TRIGGER_POWER;
    } else if (!strcmp(b, "sleep")) {
        trigger = LIBXL_TRIGGER_SLEEP;
    } else {
        fprintf(stderr, "%s is an invalid button identifier\n", b);
        exit(2);
    }

    libxl_send_trigger(ctx, domid, trigger, 0);
}

int main_button_press(int argc, char **argv)
{
    int opt;

    fprintf(stderr, "WARNING: \"button-press\" is deprecated. "
            "Please use \"trigger\"\n");


    SWITCH_FOREACH_OPT(opt, "", NULL, "button-press", 2) {
        /* No options */
    }

    button_press(find_domain(argv[optind]), argv[optind + 1]);

    return 0;
}

static void print_vcpuinfo(uint32_t tdomid,
                           const libxl_vcpuinfo *vcpuinfo,
                           uint32_t nr_cpus)
{
    char *domname;

    /*      NAME  ID  VCPU */
    domname = libxl_domid_to_name(ctx, tdomid);
    printf("%-32s %5u %5u",
           domname, tdomid, vcpuinfo->vcpuid);
    free(domname);
    if (!vcpuinfo->online) {
        /*      CPU STA */
        printf("%5c %3c%cp ", '-', '-', '-');
    } else {
        /*      CPU STA */
        printf("%5u %3c%c- ", vcpuinfo->cpu,
               vcpuinfo->running ? 'r' : '-',
               vcpuinfo->blocked ? 'b' : '-');
    }
    /*      TIM */
    printf("%9.1f  ", ((float)vcpuinfo->vcpu_time / 1e9));
    /* CPU HARD AND SOFT AFFINITY */
    print_bitmap(vcpuinfo->cpumap.map, nr_cpus, stdout);
    printf(" / ");
    print_bitmap(vcpuinfo->cpumap_soft.map, nr_cpus, stdout);
    printf("\n");
}

static void print_domain_vcpuinfo(uint32_t domid, uint32_t nr_cpus)
{
    libxl_vcpuinfo *vcpuinfo;
    int i, nb_vcpu, nrcpus;

    vcpuinfo = libxl_list_vcpu(ctx, domid, &nb_vcpu, &nrcpus);

    if (!vcpuinfo)
        return;

    for (i = 0; i < nb_vcpu; i++) {
        print_vcpuinfo(domid, &vcpuinfo[i], nr_cpus);
    }

    libxl_vcpuinfo_list_free(vcpuinfo, nb_vcpu);
}

static void vcpulist(int argc, char **argv)
{
    libxl_dominfo *dominfo;
    libxl_physinfo physinfo;
    int i, nb_domain;

    if (libxl_get_physinfo(ctx, &physinfo) != 0) {
        fprintf(stderr, "libxl_physinfo failed.\n");
        goto vcpulist_out;
    }

    printf("%-32s %5s %5s %5s %5s %9s %s\n",
           "Name", "ID", "VCPU", "CPU", "State", "Time(s)",
           "Affinity (Hard / Soft)");
    if (!argc) {
        if (!(dominfo = libxl_list_domain(ctx, &nb_domain))) {
            fprintf(stderr, "libxl_list_domain failed.\n");
            goto vcpulist_out;
        }

        for (i = 0; i<nb_domain; i++)
            print_domain_vcpuinfo(dominfo[i].domid, physinfo.nr_cpus);

        libxl_dominfo_list_free(dominfo, nb_domain);
    } else {
        for (; argc > 0; ++argv, --argc) {
            uint32_t domid = find_domain(*argv);
            print_domain_vcpuinfo(domid, physinfo.nr_cpus);
        }
    }
  vcpulist_out:
    libxl_physinfo_dispose(&physinfo);
}

int main_vcpulist(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vcpu-list", 0) {
        /* No options */
    }

    vcpulist(argc - optind, argv + optind);
    return 0;
}

int main_vcpupin(int argc, char **argv)
{
    libxl_vcpuinfo *vcpuinfo;
    libxl_bitmap cpumap_hard, cpumap_soft;;
    libxl_bitmap *soft = &cpumap_soft, *hard = &cpumap_hard;
    uint32_t domid;
    /*
     * int would be enough for vcpuid, but we don't want to
     * mess aroung range checking the return value of strtol().
     */
    long vcpuid;
    const char *vcpu, *hard_str, *soft_str;
    char *endptr;
    int opt, nb_cpu, nb_vcpu, rc = -1;

    libxl_bitmap_init(&cpumap_hard);
    libxl_bitmap_init(&cpumap_soft);

    SWITCH_FOREACH_OPT(opt, "", NULL, "vcpu-pin", 3) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    vcpu = argv[optind+1];
    hard_str = argv[optind+2];
    soft_str = (argc > optind+3) ? argv[optind+3] : NULL;

    /* Figure out with which vCPU we are dealing with */
    vcpuid = strtol(vcpu, &endptr, 10);
    if (vcpu == endptr || vcpuid < 0) {
        if (strcmp(vcpu, "all")) {
            fprintf(stderr, "Error: Invalid argument %s as VCPU.\n", vcpu);
            goto out;
        }
        vcpuid = -1;
    }

    if (libxl_cpu_bitmap_alloc(ctx, &cpumap_hard, 0) ||
        libxl_cpu_bitmap_alloc(ctx, &cpumap_soft, 0))
        goto out;

    /*
     * Syntax is: xl vcpu-pin <domid> <vcpu> <hard> <soft>
     * We want to handle all the following cases ('-' means
     * "leave it alone"):
     *  xl vcpu-pin 0 3 3,4
     *  xl vcpu-pin 0 3 3,4 -
     *  xl vcpu-pin 0 3 - 6-9
     *  xl vcpu-pin 0 3 3,4 6-9
     */

    /*
     * Hard affinity is always present. However, if it's "-", all we need
     * is passing a NULL pointer to the libxl_set_vcpuaffinity() call below.
     */
    if (!strcmp(hard_str, "-"))
        hard = NULL;
    else if (vcpupin_parse(hard_str, hard))
        goto out;
    /*
     * Soft affinity is handled similarly. Only difference: we also want
     * to pass NULL to libxl_set_vcpuaffinity() if it is not specified.
     */
    if (argc <= optind+3 || !strcmp(soft_str, "-"))
        soft = NULL;
    else if (vcpupin_parse(soft_str, soft))
        goto out;

    if (dryrun_only) {
        nb_cpu = libxl_get_online_cpus(ctx);
        if (nb_cpu < 0) {
            fprintf(stderr, "libxl_get_online_cpus failed.\n");
            goto out;
        }

        fprintf(stdout, "cpumap: ");
        if (hard)
            print_bitmap(hard->map, nb_cpu, stdout);
        else
            fprintf(stdout, "-");
        if (soft) {
            fprintf(stdout, " ");
            print_bitmap(soft->map, nb_cpu, stdout);
        }
        fprintf(stdout, "\n");

        if (ferror(stdout) || fflush(stdout)) {
            perror("stdout");
            exit(-1);
        }

        rc = 0;
        goto out;
    }

    if (vcpuid != -1) {
        if (libxl_set_vcpuaffinity(ctx, domid, vcpuid, hard, soft)) {
            fprintf(stderr, "Could not set affinity for vcpu `%ld'.\n",
                    vcpuid);
            goto out;
        }
    } else {
        if (!(vcpuinfo = libxl_list_vcpu(ctx, domid, &nb_vcpu, &nb_cpu))) {
            fprintf(stderr, "libxl_list_vcpu failed.\n");
            goto out;
        }
        if (libxl_set_vcpuaffinity_all(ctx, domid, nb_vcpu, hard, soft))
            fprintf(stderr, "Could not set affinity.\n");
        libxl_vcpuinfo_list_free(vcpuinfo, nb_vcpu);
    }

    rc = 0;
 out:
    libxl_bitmap_dispose(&cpumap_soft);
    libxl_bitmap_dispose(&cpumap_hard);
    return rc;
}

static void vcpuset(uint32_t domid, const char* nr_vcpus, int check_host)
{
    char *endptr;
    unsigned int max_vcpus, i;
    libxl_bitmap cpumap;

    max_vcpus = strtoul(nr_vcpus, &endptr, 10);
    if (nr_vcpus == endptr) {
        fprintf(stderr, "Error: Invalid argument.\n");
        return;
    }

    /*
     * Maximum amount of vCPUS the guest is allowed to set is limited
     * by the host's amount of pCPUs.
     */
    if (check_host) {
        unsigned int host_cpu = libxl_get_max_cpus(ctx);
        if (max_vcpus > host_cpu) {
            fprintf(stderr, "You are overcommmitting! You have %d physical " \
                    " CPUs and want %d vCPUs! Aborting, use --ignore-host to " \
                    " continue\n", host_cpu, max_vcpus);
            return;
        }
        /* NB: This also limits how many are set in the bitmap */
        max_vcpus = (max_vcpus > host_cpu ? host_cpu : max_vcpus);
    }
    if (libxl_cpu_bitmap_alloc(ctx, &cpumap, max_vcpus)) {
        fprintf(stderr, "libxl_cpu_bitmap_alloc failed\n");
        return;
    }
    for (i = 0; i < max_vcpus; i++)
        libxl_bitmap_set(&cpumap, i);

    if (libxl_set_vcpuonline(ctx, domid, &cpumap) < 0)
        fprintf(stderr, "libxl_set_vcpuonline failed domid=%d max_vcpus=%d\n", domid, max_vcpus);

    libxl_bitmap_dispose(&cpumap);
}

int main_vcpuset(int argc, char **argv)
{
    static struct option opts[] = {
        {"ignore-host", 0, 0, 'i'},
        {0, 0, 0, 0}
    };
    int opt, check_host = 1;

    SWITCH_FOREACH_OPT(opt, "i", opts, "vcpu-set", 2) {
    case 'i':
        check_host = 0;
        break;
    default:
        break;
    }

    vcpuset(find_domain(argv[optind]), argv[optind + 1], check_host);
    return 0;
}

static void output_xeninfo(void)
{
    const libxl_version_info *info;
    libxl_scheduler sched;

    if (!(info = libxl_get_version_info(ctx))) {
        fprintf(stderr, "libxl_get_version_info failed.\n");
        return;
    }

    if ((sched = libxl_get_scheduler(ctx)) < 0) {
        fprintf(stderr, "get_scheduler sysctl failed.\n");
        return;
    }

    printf("xen_major              : %d\n", info->xen_version_major);
    printf("xen_minor              : %d\n", info->xen_version_minor);
    printf("xen_extra              : %s\n", info->xen_version_extra);
    printf("xen_version            : %d.%d%s\n", info->xen_version_major,
           info->xen_version_minor, info->xen_version_extra);
    printf("xen_caps               : %s\n", info->capabilities);
    printf("xen_scheduler          : %s\n", libxl_scheduler_to_string(sched));
    printf("xen_pagesize           : %u\n", info->pagesize);
    printf("platform_params        : virt_start=0x%"PRIx64"\n", info->virt_start);
    printf("xen_changeset          : %s\n", info->changeset);
    printf("xen_commandline        : %s\n", info->commandline);
    printf("cc_compiler            : %s\n", info->compiler);
    printf("cc_compile_by          : %s\n", info->compile_by);
    printf("cc_compile_domain      : %s\n", info->compile_domain);
    printf("cc_compile_date        : %s\n", info->compile_date);

    return;
}

static void output_nodeinfo(void)
{
    struct utsname utsbuf;

    if (uname(&utsbuf) < 0)
        return;

    printf("host                   : %s\n", utsbuf.nodename);
    printf("release                : %s\n", utsbuf.release);
    printf("version                : %s\n", utsbuf.version);
    printf("machine                : %s\n", utsbuf.machine);
}

static void output_physinfo(void)
{
    libxl_physinfo info;
    const libxl_version_info *vinfo;
    unsigned int i;
    libxl_bitmap cpumap;
    int n = 0;

    if (libxl_get_physinfo(ctx, &info) != 0) {
        fprintf(stderr, "libxl_physinfo failed.\n");
        return;
    }
    printf("nr_cpus                : %d\n", info.nr_cpus);
    printf("max_cpu_id             : %d\n", info.max_cpu_id);
    printf("nr_nodes               : %d\n", info.nr_nodes);
    printf("cores_per_socket       : %d\n", info.cores_per_socket);
    printf("threads_per_core       : %d\n", info.threads_per_core);
    printf("cpu_mhz                : %d\n", info.cpu_khz / 1000);
    printf("hw_caps                : ");
    for (i = 0; i < 8; i++)
        printf("%08x%c", info.hw_cap[i], i < 7 ? ':' : '\n');
    printf("virt_caps              :");
    if (info.cap_hvm)
        printf(" hvm");
    if (info.cap_hvm_directio)
        printf(" hvm_directio");
    printf("\n");
    vinfo = libxl_get_version_info(ctx);
    if (vinfo) {
        i = (1 << 20) / vinfo->pagesize;
        printf("total_memory           : %"PRIu64"\n", info.total_pages / i);
        printf("free_memory            : %"PRIu64"\n", (info.free_pages - info.outstanding_pages) / i);
        printf("sharing_freed_memory   : %"PRIu64"\n", info.sharing_freed_pages / i);
        printf("sharing_used_memory    : %"PRIu64"\n", info.sharing_used_frames / i);
        printf("outstanding_claims     : %"PRIu64"\n", info.outstanding_pages / i);
    }
    if (!libxl_get_freecpus(ctx, &cpumap)) {
        libxl_for_each_bit(i, cpumap)
            if (libxl_bitmap_test(&cpumap, i))
                n++;
        printf("free_cpus              : %d\n", n);
        free(cpumap.map);
    }
    libxl_physinfo_dispose(&info);
    return;
}

static void output_numainfo(void)
{
    libxl_numainfo *info;
    int i, j, nr;

    info = libxl_get_numainfo(ctx, &nr);
    if (info == NULL) {
        fprintf(stderr, "libxl_get_numainfo failed.\n");
        return;
    }

    printf("numa_info              :\n");
    printf("node:    memsize    memfree    distances\n");

    for (i = 0; i < nr; i++) {
        if (info[i].size != LIBXL_NUMAINFO_INVALID_ENTRY) {
            printf("%4d:    %6"PRIu64"     %6"PRIu64"      %d", i,
                   info[i].size >> 20, info[i].free >> 20,
                   info[i].dists[0]);
            for (j = 1; j < info[i].num_dists; j++)
                printf(",%d", info[i].dists[j]);
            printf("\n");
        }
    }

    libxl_numainfo_list_free(info, nr);

    return;
}

static void output_topologyinfo(void)
{
    libxl_cputopology *info;
    int i, nr;

    info = libxl_get_cpu_topology(ctx, &nr);
    if (info == NULL) {
        fprintf(stderr, "libxl_get_topologyinfo failed.\n");
        return;
    }

    printf("cpu_topology           :\n");
    printf("cpu:    core    socket     node\n");

    for (i = 0; i < nr; i++) {
        if (info[i].core != LIBXL_CPUTOPOLOGY_INVALID_ENTRY)
            printf("%3d:    %4d     %4d     %4d\n", i,
                   info[i].core, info[i].socket, info[i].node);
    }

    libxl_cputopology_list_free(info, nr);

    return;
}

static void print_info(int numa)
{
    output_nodeinfo();

    output_physinfo();

    if (numa) {
        output_topologyinfo();
        output_numainfo();
    }
    output_xeninfo();

    printf("xend_config_format     : 4\n");

    return;
}

int main_info(int argc, char **argv)
{
    int opt;
    static struct option opts[] = {
        {"numa", 0, 0, 'n'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };
    int numa = 0;

    SWITCH_FOREACH_OPT(opt, "hn", opts, "info", 0) {
    case 'n':
        numa = 1;
        break;
    }

    print_info(numa);
    return 0;
}

static void sharing(const libxl_dominfo *info, int nb_domain)
{
    int i;

    printf("Name                                        ID   Mem Shared\n");

    for (i = 0; i < nb_domain; i++) {
        char *domname;
        unsigned shutdown_reason;
        domname = libxl_domid_to_name(ctx, info[i].domid);
        shutdown_reason = info[i].shutdown ? info[i].shutdown_reason : 0;
        printf("%-40s %5d %5lu  %5lu\n",
                domname,
                info[i].domid,
                (unsigned long) ((info[i].current_memkb +
                    info[i].outstanding_memkb) / 1024),
                (unsigned long) (info[i].shared_memkb / 1024));
        free(domname);
    }
}

int main_sharing(int argc, char **argv)
{
    int opt = 0;
    libxl_dominfo info_buf;
    libxl_dominfo *info, *info_free = NULL;
    int nb_domain, rc;

    SWITCH_FOREACH_OPT(opt, "", NULL, "sharing", 0) {
        /* No options */
    }

    if (optind >= argc) {
        info = libxl_list_domain(ctx, &nb_domain);
        if (!info) {
            fprintf(stderr, "libxl_list_domain failed.\n");
            return 1;
        }
        info_free = info;
    } else if (optind == argc-1) {
        uint32_t domid = find_domain(argv[optind]);
        rc = libxl_domain_info(ctx, &info_buf, domid);
        if (rc == ERROR_INVAL) {
            fprintf(stderr, "Error: Domain \'%s\' does not exist.\n",
                argv[optind]);
            return -rc;
        }
        if (rc) {
            fprintf(stderr, "libxl_domain_info failed (code %d).\n", rc);
            return -rc;
        }
        info = &info_buf;
        nb_domain = 1;
    } else {
        help("sharing");
        return 2;
    }

    sharing(info, nb_domain);

    if (info_free)
        libxl_dominfo_list_free(info_free, nb_domain);
    else
        libxl_dominfo_dispose(info);

    return 0;
}

static int sched_domain_get(libxl_scheduler sched, int domid,
                            libxl_domain_sched_params *scinfo)
{
    int rc;

    rc = libxl_domain_sched_params_get(ctx, domid, scinfo);
    if (rc) {
        fprintf(stderr, "libxl_domain_sched_params_get failed.\n");
        return rc;
    }
    if (scinfo->sched != sched) {
        fprintf(stderr, "libxl_domain_sched_params_get returned %s not %s.\n",
                libxl_scheduler_to_string(scinfo->sched),
                libxl_scheduler_to_string(sched));
        return ERROR_INVAL;
    }

    return 0;
}

static int sched_domain_set(int domid, const libxl_domain_sched_params *scinfo)
{
    int rc;

    rc = libxl_domain_sched_params_set(ctx, domid, scinfo);
    if (rc)
        fprintf(stderr, "libxl_domain_sched_params_set failed.\n");

    return rc;
}

static int sched_credit_params_set(int poolid, libxl_sched_credit_params *scinfo)
{
    int rc;

    rc = libxl_sched_credit_params_set(ctx, poolid, scinfo);
    if (rc)
        fprintf(stderr, "libxl_sched_credit_params_set failed.\n");

    return rc;
}

static int sched_credit_params_get(int poolid, libxl_sched_credit_params *scinfo)
{
    int rc;

    rc = libxl_sched_credit_params_get(ctx, poolid, scinfo);
    if (rc)
        fprintf(stderr, "libxl_sched_credit_params_get failed.\n");

    return rc;
}

static int sched_credit_domain_output(int domid)
{
    char *domname;
    libxl_domain_sched_params scinfo;
    int rc;

    if (domid < 0) {
        printf("%-33s %4s %6s %4s\n", "Name", "ID", "Weight", "Cap");
        return 0;
    }
    rc = sched_domain_get(LIBXL_SCHEDULER_CREDIT, domid, &scinfo);
    if (rc)
        return rc;
    domname = libxl_domid_to_name(ctx, domid);
    printf("%-33s %4d %6d %4d\n",
        domname,
        domid,
        scinfo.weight,
        scinfo.cap);
    free(domname);
    libxl_domain_sched_params_dispose(&scinfo);
    return 0;
}

static int sched_credit_pool_output(uint32_t poolid)
{
    libxl_sched_credit_params scparam;
    char *poolname;
    int rc;

    poolname = libxl_cpupoolid_to_name(ctx, poolid);
    rc = sched_credit_params_get(poolid, &scparam);
    if (rc) {
        printf("Cpupool %s: [sched params unavailable]\n",
               poolname);
    } else {
        printf("Cpupool %s: tslice=%dms ratelimit=%dus\n",
               poolname,
               scparam.tslice_ms,
               scparam.ratelimit_us);
    }
    free(poolname);
    return 0;
}

static int sched_credit2_domain_output(
    int domid)
{
    char *domname;
    libxl_domain_sched_params scinfo;
    int rc;

    if (domid < 0) {
        printf("%-33s %4s %6s\n", "Name", "ID", "Weight");
        return 0;
    }
    rc = sched_domain_get(LIBXL_SCHEDULER_CREDIT2, domid, &scinfo);
    if (rc)
        return rc;
    domname = libxl_domid_to_name(ctx, domid);
    printf("%-33s %4d %6d\n",
        domname,
        domid,
        scinfo.weight);
    free(domname);
    libxl_domain_sched_params_dispose(&scinfo);
    return 0;
}

static int sched_sedf_domain_output(
    int domid)
{
    char *domname;
    libxl_domain_sched_params scinfo;
    int rc;

    if (domid < 0) {
        printf("%-33s %4s %6s %-6s %7s %5s %6s\n", "Name", "ID", "Period",
               "Slice", "Latency", "Extra", "Weight");
        return 0;
    }
    rc = sched_domain_get(LIBXL_SCHEDULER_SEDF, domid, &scinfo);
    if (rc)
        return rc;
    domname = libxl_domid_to_name(ctx, domid);
    printf("%-33s %4d %6d %6d %7d %5d %6d\n",
        domname,
        domid,
        scinfo.period,
        scinfo.slice,
        scinfo.latency,
        scinfo.extratime,
        scinfo.weight);
    free(domname);
    libxl_domain_sched_params_dispose(&scinfo);
    return 0;
}

static int sched_rtds_domain_output(
    int domid)
{
    char *domname;
    libxl_domain_sched_params scinfo;
    int rc = 0;

    if (domid < 0) {
        printf("%-33s %4s %9s %9s\n", "Name", "ID", "Period", "Budget");
        return 0;
    }

    libxl_domain_sched_params_init(&scinfo);
    rc = sched_domain_get(LIBXL_SCHEDULER_RTDS, domid, &scinfo);
    if (rc)
        goto out;

    domname = libxl_domid_to_name(ctx, domid);
    printf("%-33s %4d %9d %9d\n",
        domname,
        domid,
        scinfo.period,
        scinfo.budget);
    free(domname);

out:
    libxl_domain_sched_params_dispose(&scinfo);
    return rc;
}

static int sched_rtds_pool_output(uint32_t poolid)
{
    char *poolname;

    poolname = libxl_cpupoolid_to_name(ctx, poolid);
    printf("Cpupool %s: sched=RTDS\n", poolname);

    free(poolname);
    return 0;
}

static int sched_default_pool_output(uint32_t poolid)
{
    char *poolname;

    poolname = libxl_cpupoolid_to_name(ctx, poolid);
    printf("Cpupool %s:\n",
           poolname);
    free(poolname);
    return 0;
}

static int sched_domain_output(libxl_scheduler sched, int (*output)(int),
                               int (*pooloutput)(uint32_t), const char *cpupool)
{
    libxl_dominfo *info;
    libxl_cpupoolinfo *poolinfo = NULL;
    uint32_t poolid;
    int nb_domain, n_pools = 0, i, p;
    int rc = 0;

    if (cpupool) {
        if (libxl_cpupool_qualifier_to_cpupoolid(ctx, cpupool, &poolid, NULL) ||
            !libxl_cpupoolid_is_valid(ctx, poolid)) {
            fprintf(stderr, "unknown cpupool \'%s\'\n", cpupool);
            return -ERROR_FAIL;
        }
    }

    info = libxl_list_domain(ctx, &nb_domain);
    if (!info) {
        fprintf(stderr, "libxl_list_domain failed.\n");
        return 1;
    }
    poolinfo = libxl_list_cpupool(ctx, &n_pools);
    if (!poolinfo) {
        fprintf(stderr, "error getting cpupool info\n");
        libxl_dominfo_list_free(info, nb_domain);
        return -ERROR_NOMEM;
    }

    for (p = 0; !rc && (p < n_pools); p++) {
        if ((poolinfo[p].sched != sched) ||
            (cpupool && (poolid != poolinfo[p].poolid)))
            continue;

        pooloutput(poolinfo[p].poolid);

        output(-1);
        for (i = 0; i < nb_domain; i++) {
            if (info[i].cpupool != poolinfo[p].poolid)
                continue;
            rc = output(info[i].domid);
            if (rc)
                break;
        }
    }

    libxl_cpupoolinfo_list_free(poolinfo, n_pools);
    libxl_dominfo_list_free(info, nb_domain);
    return 0;
}

/* 
 * <nothing>             : List all domain params and sched params from all pools
 * -d [domid]            : List domain params for domain
 * -d [domid] [params]   : Set domain params for domain
 * -p [pool]             : list all domains and sched params for pool
 * -s                    : List sched params for poolid 0
 * -s [params]           : Set sched params for poolid 0
 * -p [pool] -s          : List sched params for pool
 * -p [pool] -s [params] : Set sched params for pool
 * -p [pool] -d...       : Illegal
 */
int main_sched_credit(int argc, char **argv)
{
    const char *dom = NULL;
    const char *cpupool = NULL;
    int weight = 256, cap = 0, opt_w = 0, opt_c = 0;
    int opt_s = 0;
    int tslice = 0, opt_t = 0, ratelimit = 0, opt_r = 0;
    int opt, rc;
    static struct option opts[] = {
        {"domain", 1, 0, 'd'},
        {"weight", 1, 0, 'w'},
        {"cap", 1, 0, 'c'},
        {"schedparam", 0, 0, 's'},
        {"tslice_ms", 1, 0, 't'},
        {"ratelimit_us", 1, 0, 'r'},
        {"cpupool", 1, 0, 'p'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    SWITCH_FOREACH_OPT(opt, "d:w:c:p:t:r:hs", opts, "sched-credit", 0) {
    case 'd':
        dom = optarg;
        break;
    case 'w':
        weight = strtol(optarg, NULL, 10);
        opt_w = 1;
        break;
    case 'c':
        cap = strtol(optarg, NULL, 10);
        opt_c = 1;
        break;
    case 't':
        tslice = strtol(optarg, NULL, 10);
        opt_t = 1;
        break;
    case 'r':
        ratelimit = strtol(optarg, NULL, 10);
        opt_r = 1;
        break;
    case 's':
        opt_s = 1;
        break;
    case 'p':
        cpupool = optarg;
        break;
    }

    if ((cpupool || opt_s) && (dom || opt_w || opt_c)) {
        fprintf(stderr, "Specifying a cpupool or schedparam is not "
                "allowed with domain options.\n");
        return 1;
    }
    if (!dom && (opt_w || opt_c)) {
        fprintf(stderr, "Must specify a domain.\n");
        return 1;
    }
    if (!opt_s && (opt_t || opt_r)) {
        fprintf(stderr, "Must specify schedparam to set schedule "
                "parameter values.\n");
        return 1;
    }

    if (opt_s) {
        libxl_sched_credit_params scparam;
        uint32_t poolid = 0;

        if (cpupool) {
            if (libxl_cpupool_qualifier_to_cpupoolid(ctx, cpupool,
                                                     &poolid, NULL) ||
                !libxl_cpupoolid_is_valid(ctx, poolid)) {
                fprintf(stderr, "unknown cpupool \'%s\'\n", cpupool);
                return -ERROR_FAIL;
            }
        }

        if (!opt_t && !opt_r) { /* Output scheduling parameters */
            return -sched_credit_pool_output(poolid);
        } else { /* Set scheduling parameters*/
            rc = sched_credit_params_get(poolid, &scparam);
            if (rc)
                return -rc;

            if (opt_t)
                scparam.tslice_ms = tslice;

            if (opt_r)
                scparam.ratelimit_us = ratelimit;

            rc = sched_credit_params_set(poolid, &scparam);
            if (rc)
                return -rc;
        }
    } else if (!dom) { /* list all domain's credit scheduler info */
        return -sched_domain_output(LIBXL_SCHEDULER_CREDIT,
                                    sched_credit_domain_output,
                                    sched_credit_pool_output,
                                    cpupool);
    } else {
        uint32_t domid = find_domain(dom);

        if (!opt_w && !opt_c) { /* output credit scheduler info */
            sched_credit_domain_output(-1);
            return -sched_credit_domain_output(domid);
        } else { /* set credit scheduler paramaters */
            libxl_domain_sched_params scinfo;
            libxl_domain_sched_params_init(&scinfo);
            scinfo.sched = LIBXL_SCHEDULER_CREDIT;
            if (opt_w)
                scinfo.weight = weight;
            if (opt_c)
                scinfo.cap = cap;
            rc = sched_domain_set(domid, &scinfo);
            libxl_domain_sched_params_dispose(&scinfo);
            if (rc)
                return -rc;
        }
    }

    return 0;
}

int main_sched_credit2(int argc, char **argv)
{
    const char *dom = NULL;
    const char *cpupool = NULL;
    int weight = 256, opt_w = 0;
    int opt, rc;
    static struct option opts[] = {
        {"domain", 1, 0, 'd'},
        {"weight", 1, 0, 'w'},
        {"cpupool", 1, 0, 'p'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    SWITCH_FOREACH_OPT(opt, "d:w:p:h", opts, "sched-credit2", 0) {
    case 'd':
        dom = optarg;
        break;
    case 'w':
        weight = strtol(optarg, NULL, 10);
        opt_w = 1;
        break;
    case 'p':
        cpupool = optarg;
        break;
    }

    if (cpupool && (dom || opt_w)) {
        fprintf(stderr, "Specifying a cpupool is not allowed with other "
                "options.\n");
        return 1;
    }
    if (!dom && opt_w) {
        fprintf(stderr, "Must specify a domain.\n");
        return 1;
    }

    if (!dom) { /* list all domain's credit scheduler info */
        return -sched_domain_output(LIBXL_SCHEDULER_CREDIT2,
                                    sched_credit2_domain_output,
                                    sched_default_pool_output,
                                    cpupool);
    } else {
        uint32_t domid = find_domain(dom);

        if (!opt_w) { /* output credit2 scheduler info */
            sched_credit2_domain_output(-1);
            return -sched_credit2_domain_output(domid);
        } else { /* set credit2 scheduler paramaters */
            libxl_domain_sched_params scinfo;
            libxl_domain_sched_params_init(&scinfo);
            scinfo.sched = LIBXL_SCHEDULER_CREDIT2;
            if (opt_w)
                scinfo.weight = weight;
            rc = sched_domain_set(domid, &scinfo);
            libxl_domain_sched_params_dispose(&scinfo);
            if (rc)
                return -rc;
        }
    }

    return 0;
}

int main_sched_sedf(int argc, char **argv)
{
    const char *dom = NULL;
    const char *cpupool = NULL;
    int period = 0, opt_p = 0;
    int slice = 0, opt_s = 0;
    int latency = 0, opt_l = 0;
    int extra = 0, opt_e = 0;
    int weight = 0, opt_w = 0;
    int opt, rc;
    static struct option opts[] = {
        {"period", 1, 0, 'p'},
        {"slice", 1, 0, 's'},
        {"latency", 1, 0, 'l'},
        {"extra", 1, 0, 'e'},
        {"weight", 1, 0, 'w'},
        {"cpupool", 1, 0, 'c'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    SWITCH_FOREACH_OPT(opt, "d:p:s:l:e:w:c:h", opts, "sched-sedf", 0) {
    case 'd':
        dom = optarg;
        break;
    case 'p':
        period = strtol(optarg, NULL, 10);
        opt_p = 1;
        break;
    case 's':
        slice = strtol(optarg, NULL, 10);
        opt_s = 1;
        break;
    case 'l':
        latency = strtol(optarg, NULL, 10);
        opt_l = 1;
        break;
    case 'e':
        extra = strtol(optarg, NULL, 10);
        opt_e = 1;
        break;
    case 'w':
        weight = strtol(optarg, NULL, 10);
        opt_w = 1;
        break;
    case 'c':
        cpupool = optarg;
        break;
    }

    if (cpupool && (dom || opt_p || opt_s || opt_l || opt_e || opt_w)) {
        fprintf(stderr, "Specifying a cpupool is not allowed with other "
                "options.\n");
        return 1;
    }
    if (!dom && (opt_p || opt_s || opt_l || opt_e || opt_w)) {
        fprintf(stderr, "Must specify a domain.\n");
        return 1;
    }
    if (opt_w && (opt_p || opt_s)) {
        fprintf(stderr, "Specifying a weight AND period or slice is not "
                "allowed.\n");
    }

    if (!dom) { /* list all domain's credit scheduler info */
        return -sched_domain_output(LIBXL_SCHEDULER_SEDF,
                                    sched_sedf_domain_output,
                                    sched_default_pool_output,
                                    cpupool);
    } else {
        uint32_t domid = find_domain(dom);

        if (!opt_p && !opt_s && !opt_l && !opt_e && !opt_w) {
            /* output sedf scheduler info */
            sched_sedf_domain_output(-1);
            return -sched_sedf_domain_output(domid);
        } else { /* set sedf scheduler paramaters */
            libxl_domain_sched_params scinfo;
            libxl_domain_sched_params_init(&scinfo);
            scinfo.sched = LIBXL_SCHEDULER_SEDF;

            if (opt_p) {
                scinfo.period = period;
                scinfo.weight = 0;
            }
            if (opt_s) {
                scinfo.slice = slice;
                scinfo.weight = 0;
            }
            if (opt_l)
                scinfo.latency = latency;
            if (opt_e)
                scinfo.extratime = extra;
            if (opt_w) {
                scinfo.weight = weight;
                scinfo.period = 0;
                scinfo.slice = 0;
            }
            rc = sched_domain_set(domid, &scinfo);
            libxl_domain_sched_params_dispose(&scinfo);
            if (rc)
                return -rc;
        }
    }

    return 0;
}

/*
 * <nothing>            : List all domain paramters and sched params
 * -d [domid]           : List domain params for domain
 * -d [domid] [params]  : Set domain params for domain
 */
int main_sched_rtds(int argc, char **argv)
{
    const char *dom = NULL;
    const char *cpupool = NULL;
    int period = 0; /* period is in microsecond */
    int budget = 0; /* budget is in microsecond */
    bool opt_p = false;
    bool opt_b = false;
    int opt, rc;
    static struct option opts[] = {
        {"domain", 1, 0, 'd'},
        {"period", 1, 0, 'p'},
        {"budget", 1, 0, 'b'},
        {"cpupool", 1, 0, 'c'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    SWITCH_FOREACH_OPT(opt, "d:p:b:c:h", opts, "sched-rtds", 0) {
    case 'd':
        dom = optarg;
        break;
    case 'p':
        period = strtol(optarg, NULL, 10);
        opt_p = 1;
        break;
    case 'b':
        budget = strtol(optarg, NULL, 10);
        opt_b = 1;
        break;
    case 'c':
        cpupool = optarg;
        break;
    }

    if (cpupool && (dom || opt_p || opt_b)) {
        fprintf(stderr, "Specifying a cpupool is not allowed with "
                "other options.\n");
        return 1;
    }
    if (!dom && (opt_p || opt_b)) {
        fprintf(stderr, "Must specify a domain.\n");
        return 1;
    }
    if (opt_p != opt_b) {
        fprintf(stderr, "Must specify period and budget\n");
        return 1;
    }

    if (!dom) { /* list all domain's rt scheduler info */
        return -sched_domain_output(LIBXL_SCHEDULER_RTDS,
                                    sched_rtds_domain_output,
                                    sched_rtds_pool_output,
                                    cpupool);
    } else {
        uint32_t domid = find_domain(dom);
        if (!opt_p && !opt_b) { /* output rt scheduler info */
            sched_rtds_domain_output(-1);
            return -sched_rtds_domain_output(domid);
        } else { /* set rt scheduler paramaters */
            libxl_domain_sched_params scinfo;
            libxl_domain_sched_params_init(&scinfo);
            scinfo.sched = LIBXL_SCHEDULER_RTDS;
            scinfo.period = period;
            scinfo.budget = budget;

            rc = sched_domain_set(domid, &scinfo);
            libxl_domain_sched_params_dispose(&scinfo);
            if (rc)
                return -rc;
        }
    }

    return 0;
}

int main_domid(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    const char *domname = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "domid", 1) {
        /* No options */
    }

    domname = argv[optind];

    if (libxl_name_to_domid(ctx, domname, &domid)) {
        fprintf(stderr, "Can't get domid of domain name '%s', maybe this domain does not exist.\n", domname);
        return 1;
    }

    printf("%d\n", domid);

    return 0;
}

int main_domname(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    char *domname = NULL;
    char *endptr = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "domname", 1) {
        /* No options */
    }

    domid = strtol(argv[optind], &endptr, 10);
    if (domid == 0 && !strcmp(endptr, argv[optind])) {
        /*no digits at all*/
        fprintf(stderr, "Invalid domain id.\n\n");
        return 1;
    }

    domname = libxl_domid_to_name(ctx, domid);
    if (!domname) {
        fprintf(stderr, "Can't get domain name of domain id '%d', maybe this domain does not exist.\n", domid);
        return 1;
    }

    printf("%s\n", domname);
    free(domname);

    return 0;
}

int main_rename(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    const char *dom, *new_name;

    SWITCH_FOREACH_OPT(opt, "", NULL, "rename", 2) {
        /* No options */
    }

    dom = argv[optind++];
    new_name = argv[optind];

    domid = find_domain(dom);
    if (libxl_domain_rename(ctx, domid, common_domname, new_name)) {
        fprintf(stderr, "Can't rename domain '%s'.\n", dom);
        return 1;
    }

    return 0;
}

int main_trigger(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    char *endptr = NULL;
    int vcpuid = 0;
    const char *trigger_name = NULL;
    libxl_trigger trigger;

    SWITCH_FOREACH_OPT(opt, "", NULL, "trigger", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);

    trigger_name = argv[optind++];
    if (libxl_trigger_from_string(trigger_name, &trigger)) {
        fprintf(stderr, "Invalid trigger \"%s\"\n", trigger_name);
        return -1;
    }

    if (argv[optind]) {
        vcpuid = strtol(argv[optind], &endptr, 10);
        if (vcpuid == 0 && !strcmp(endptr, argv[optind])) {
            fprintf(stderr, "Invalid vcpuid, using default vcpuid=0.\n\n");
        }
    }

    libxl_send_trigger(ctx, domid, trigger, vcpuid);

    return 0;
}


int main_sysrq(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    const char *sysrq = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "sysrq", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);

    sysrq = argv[optind];

    if (sysrq[1] != '\0') {
        fprintf(stderr, "Invalid sysrq.\n\n");
        help("sysrq");
        return 1;
    }

    libxl_send_sysrq(ctx, domid, sysrq[0]);

    return 0;
}

int main_debug_keys(int argc, char **argv)
{
    int opt;
    char *keys;

    SWITCH_FOREACH_OPT(opt, "", NULL, "debug-keys", 1) {
        /* No options */
    }

    keys = argv[optind];

    if (libxl_send_debug_keys(ctx, keys)) {
        fprintf(stderr, "cannot send debug keys: %s\n", keys);
        return 1;
    }

    return 0;
}

int main_dmesg(int argc, char **argv)
{
    unsigned int clear = 0;
    libxl_xen_console_reader *cr;
    char *line;
    int opt, ret = 1;

    SWITCH_FOREACH_OPT(opt, "c", NULL, "dmesg", 0) {
    case 'c':
        clear = 1;
        break;
    }

    cr = libxl_xen_console_read_start(ctx, clear);
    if (!cr)
        goto finish;

    while ((ret = libxl_xen_console_read_line(ctx, cr, &line)) > 0)
        printf("%s", line);

finish:
    if (cr)
        libxl_xen_console_read_finish(ctx, cr);
    return ret;
}

int main_top(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "top", 0) {
        /* No options */
    }

    return system("xentop");
}

int main_networkattach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    libxl_device_nic nic;
    XLU_Config *config = 0;
    char *endptr, *oparg;
    const char *tok;
    int i;
    unsigned int val;

    SWITCH_FOREACH_OPT(opt, "", NULL, "network-attach", 1) {
        /* No options */
    }

    if (argc-optind > 11) {
        help("network-attach");
        return 0;
    }

    domid = find_domain(argv[optind]);

    config= xlu_cfg_init(stderr, "command line");
    if (!config) {
        fprintf(stderr, "Failed to allocate for configuration\n");
        return 1;
    }

    libxl_device_nic_init(&nic);
    set_default_nic_values(&nic);

    for (argv += optind+1, argc -= optind+1; argc > 0; ++argv, --argc) {
        if (MATCH_OPTION("type", *argv, oparg)) {
            if (!strcmp("vif", oparg)) {
                nic.nictype = LIBXL_NIC_TYPE_VIF;
            } else if (!strcmp("ioemu", oparg)) {
                nic.nictype = LIBXL_NIC_TYPE_VIF_IOEMU;
            } else {
                fprintf(stderr, "Invalid parameter `type'.\n");
                return 1;
            }
        } else if (MATCH_OPTION("mac", *argv, oparg)) {
            tok = strtok(oparg, ":");
            for (i = 0; tok && i < 6; tok = strtok(NULL, ":"), ++i) {
                val = strtoul(tok, &endptr, 16);
                if ((tok == endptr) || (val > 255)) {
                    fprintf(stderr, "Invalid parameter `mac'.\n");
                    return 1;
                }
                nic.mac[i] = val;
            }
        } else if (MATCH_OPTION("bridge", *argv, oparg)) {
            replace_string(&nic.bridge, oparg);
        } else if (MATCH_OPTION("netdev", *argv, oparg)) {
            fprintf(stderr, "the netdev parameter is deprecated, "
                            "please use gatewaydev instead\n");
            replace_string(&nic.gatewaydev, oparg);
        } else if (MATCH_OPTION("gatewaydev", *argv, oparg)) {
            replace_string(&nic.gatewaydev, oparg);
        } else if (MATCH_OPTION("ip", *argv, oparg)) {
            replace_string(&nic.ip, oparg);
        } else if (MATCH_OPTION("script", *argv, oparg)) {
            replace_string(&nic.script, oparg);
        } else if (MATCH_OPTION("backend", *argv, oparg)) {
            replace_string(&nic.backend_domname, oparg);
        } else if (MATCH_OPTION("vifname", *argv, oparg)) {
            replace_string(&nic.ifname, oparg);
        } else if (MATCH_OPTION("model", *argv, oparg)) {
            replace_string(&nic.model, oparg);
        } else if (MATCH_OPTION("rate", *argv, oparg)) {
            parse_vif_rate(&config, oparg, &nic);
        } else if (MATCH_OPTION("accel", *argv, oparg)) {
        } else {
            fprintf(stderr, "unrecognized argument `%s'\n", *argv);
            return 1;
        }
    }

    if (dryrun_only) {
        char *json = libxl_device_nic_to_json(ctx, &nic);
        printf("vif: %s\n", json);
        free(json);
        libxl_device_nic_dispose(&nic);
        if (ferror(stdout) || fflush(stdout)) { perror("stdout"); exit(-1); }
        return 0;
    }

    if (libxl_device_nic_add(ctx, domid, &nic, 0)) {
        fprintf(stderr, "libxl_device_nic_add failed.\n");
        return 1;
    }
    libxl_device_nic_dispose(&nic);
    xlu_cfg_destroy(config);
    return 0;
}

int main_networklist(int argc, char **argv)
{
    int opt;
    libxl_device_nic *nics;
    libxl_nicinfo nicinfo;
    int nb, i;

    SWITCH_FOREACH_OPT(opt, "", NULL, "network-list", 1) {
        /* No options */
    }

    /*      Idx  BE   MAC   Hdl  Sta  evch txr/rxr  BE-path */
    printf("%-3s %-2s %-17s %-6s %-5s %-6s %5s/%-5s %-30s\n",
           "Idx", "BE", "Mac Addr.", "handle", "state", "evt-ch", "tx-", "rx-ring-ref", "BE-path");
    for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
        uint32_t domid = find_domain(*argv);
        nics = libxl_device_nic_list(ctx, domid, &nb);
        if (!nics) {
            continue;
        }
        for (i = 0; i < nb; ++i) {
            if (!libxl_device_nic_getinfo(ctx, domid, &nics[i], &nicinfo)) {
                /* Idx BE */
                printf("%-3d %-2d ", nicinfo.devid, nicinfo.backend_id);
                /* MAC */
                printf(LIBXL_MAC_FMT, LIBXL_MAC_BYTES(nics[i].mac));
                /* Hdl  Sta  evch txr/rxr  BE-path */
                printf("%6d %5d %6d %5d/%-11d %-30s\n",
                       nicinfo.devid, nicinfo.state, nicinfo.evtch,
                       nicinfo.rref_tx, nicinfo.rref_rx, nicinfo.backend);
                libxl_nicinfo_dispose(&nicinfo);
            }
            libxl_device_nic_dispose(&nics[i]);
        }
        free(nics);
    }
    return 0;
}

int main_networkdetach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    libxl_device_nic nic;

    SWITCH_FOREACH_OPT(opt, "", NULL, "network-detach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);

    if (!strchr(argv[optind+1], ':')) {
        if (libxl_devid_to_device_nic(ctx, domid, atoi(argv[optind+1]), &nic)) {
            fprintf(stderr, "Unknown device %s.\n", argv[optind+1]);
            return 1;
        }
    } else {
        if (libxl_mac_to_device_nic(ctx, domid, argv[optind+1], &nic)) {
            fprintf(stderr, "Unknown device %s.\n", argv[optind+1]);
            return 1;
        }
    }
    if (libxl_device_nic_remove(ctx, domid, &nic, 0)) {
        fprintf(stderr, "libxl_device_nic_del failed.\n");
        return 1;
    }
    libxl_device_nic_dispose(&nic);
    return 0;
}

int main_channellist(int argc, char **argv)
{
    int opt;
    libxl_device_channel *channels;
    libxl_channelinfo channelinfo;
    int nb, i;

    SWITCH_FOREACH_OPT(opt, "", NULL, "channel-list", 1) {
        /* No options */
    }

    /*      Idx BE state evt-ch ring-ref connection params*/
    printf("%-3s %-2s %-5s %-6s %8s %-10s %-30s\n",
           "Idx", "BE", "state", "evt-ch", "ring-ref", "connection", "");
    for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
        uint32_t domid = find_domain(*argv);
        channels = libxl_device_channel_list(ctx, domid, &nb);
        if (!channels)
            continue;
        for (i = 0; i < nb; ++i) {
            if (!libxl_device_channel_getinfo(ctx, domid, &channels[i],
                &channelinfo)) {
                printf("%-3d %-2d ", channels[i].devid, channelinfo.backend_id);
                printf("%-5d ", channelinfo.state);
                printf("%-6d %-8d ", channelinfo.evtch, channelinfo.rref);
                printf("%-10s ", libxl_channel_connection_to_string(
                       channels[i].connection));
                switch (channels[i].connection) {
                    case LIBXL_CHANNEL_CONNECTION_PTY:
                        printf("%-30s ", channelinfo.u.pty.path);
                        break;
                    default:
                        break;
                }
                printf("\n");
                libxl_channelinfo_dispose(&channelinfo);
            }
            libxl_device_channel_dispose(&channels[i]);
        }
        free(channels);
    }
    return 0;
}

int main_blockattach(int argc, char **argv)
{
    int opt;
    uint32_t fe_domid;
    libxl_device_disk disk;
    XLU_Config *config = 0;

    SWITCH_FOREACH_OPT(opt, "", NULL, "block-attach", 2) {
        /* No options */
    }

    if (libxl_domain_qualifier_to_domid(ctx, argv[optind], &fe_domid) < 0) {
        fprintf(stderr, "%s is an invalid domain identifier\n", argv[optind]);
        return 1;
    }
    optind++;

    parse_disk_config_multistring
        (&config, argc-optind, (const char* const*)argv + optind, &disk);

    if (dryrun_only) {
        char *json = libxl_device_disk_to_json(ctx, &disk);
        printf("disk: %s\n", json);
        free(json);
        if (ferror(stdout) || fflush(stdout)) { perror("stdout"); exit(-1); }
        return 0;
    }

    if (libxl_device_disk_add(ctx, fe_domid, &disk, 0)) {
        fprintf(stderr, "libxl_device_disk_add failed.\n");
        return 1;
    }
    return 0;
}

int main_blocklist(int argc, char **argv)
{
    int opt;
    int i, nb;
    libxl_device_disk *disks;
    libxl_diskinfo diskinfo;

    SWITCH_FOREACH_OPT(opt, "", NULL, "block-list", 1) {
        /* No options */
    }

    printf("%-5s %-3s %-6s %-5s %-6s %-8s %-30s\n",
           "Vdev", "BE", "handle", "state", "evt-ch", "ring-ref", "BE-path");
    for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
        uint32_t domid;
        if (libxl_domain_qualifier_to_domid(ctx, *argv, &domid) < 0) {
            fprintf(stderr, "%s is an invalid domain identifier\n", *argv);
            continue;
        }
        disks = libxl_device_disk_list(ctx, domid, &nb);
        if (!disks) {
            continue;
        }
        for (i=0; i<nb; i++) {
            if (!libxl_device_disk_getinfo(ctx, domid, &disks[i], &diskinfo)) {
                /*      Vdev BE   hdl  st   evch rref BE-path*/
                printf("%-5d %-3d %-6d %-5d %-6d %-8d %-30s\n",
                       diskinfo.devid, diskinfo.backend_id, diskinfo.frontend_id,
                       diskinfo.state, diskinfo.evtch, diskinfo.rref, diskinfo.backend);
                libxl_diskinfo_dispose(&diskinfo);
            }
            libxl_device_disk_dispose(&disks[i]);
        }
        free(disks);
    }
    return 0;
}

int main_blockdetach(int argc, char **argv)
{
    uint32_t domid;
    int opt, rc = 0;
    libxl_device_disk disk;

    SWITCH_FOREACH_OPT(opt, "", NULL, "block-detach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);

    if (libxl_vdev_to_device_disk(ctx, domid, argv[optind+1], &disk)) {
        fprintf(stderr, "Error: Device %s not connected.\n", argv[optind+1]);
        return 1;
    }
    rc = libxl_device_disk_remove(ctx, domid, &disk, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_disk_remove failed.\n");
        return 1;
    }
    libxl_device_disk_dispose(&disk);
    return rc;
}

int main_vtpmattach(int argc, char **argv)
{
    int opt;
    libxl_device_vtpm vtpm;
    char *oparg;
    uint32_t domid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vtpm-attach", 1) {
        /* No options */
    }

    if (libxl_domain_qualifier_to_domid(ctx, argv[optind], &domid) < 0) {
        fprintf(stderr, "%s is an invalid domain identifier\n", argv[optind]);
        return 1;
    }
    ++optind;

    libxl_device_vtpm_init(&vtpm);
    for (argv += optind, argc -= optind; argc > 0; ++argv, --argc) {
        if (MATCH_OPTION("uuid", *argv, oparg)) {
            if(libxl_uuid_from_string(&(vtpm.uuid), oparg)) {
                fprintf(stderr, "Invalid uuid specified (%s)\n", oparg);
                return 1;
            }
        } else if (MATCH_OPTION("backend", *argv, oparg)) {
            replace_string(&vtpm.backend_domname, oparg);
        } else {
            fprintf(stderr, "unrecognized argument `%s'\n", *argv);
            return 1;
        }
    }

    if(dryrun_only) {
       char* json = libxl_device_vtpm_to_json(ctx, &vtpm);
       printf("vtpm: %s\n", json);
       free(json);
       libxl_device_vtpm_dispose(&vtpm);
       if (ferror(stdout) || fflush(stdout)) { perror("stdout"); exit(-1); }
       return 0;
    }

    if (libxl_device_vtpm_add(ctx, domid, &vtpm, 0)) {
        fprintf(stderr, "libxl_device_vtpm_add failed.\n");
        return 1;
    }
    libxl_device_vtpm_dispose(&vtpm);
    return 0;
}

int main_vtpmlist(int argc, char **argv)
{
    int opt;
    libxl_device_vtpm *vtpms;
    libxl_vtpminfo vtpminfo;
    int nb, i;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vtpm-list", 1) {
        /* No options */
    }

    /*      Idx  BE   UUID   Hdl  Sta  evch rref  BE-path */
    printf("%-3s %-2s %-36s %-6s %-5s %-6s %-5s %-10s\n",
           "Idx", "BE", "Uuid", "handle", "state", "evt-ch", "ring-ref", "BE-path");
    for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
        uint32_t domid;
        if (libxl_domain_qualifier_to_domid(ctx, *argv, &domid) < 0) {
            fprintf(stderr, "%s is an invalid domain identifier\n", *argv);
            continue;
        }
        if (!(vtpms = libxl_device_vtpm_list(ctx, domid, &nb))) {
            continue;
        }
        for (i = 0; i < nb; ++i) {
           if(!libxl_device_vtpm_getinfo(ctx, domid, &vtpms[i], &vtpminfo)) {
              /*      Idx  BE     UUID             Hdl Sta evch rref BE-path*/
              printf("%-3d %-2d " LIBXL_UUID_FMT " %6d %5d %6d %8d %-30s\n",
                    vtpminfo.devid, vtpminfo.backend_id,
                    LIBXL_UUID_BYTES(vtpminfo.uuid),
                    vtpminfo.devid, vtpminfo.state, vtpminfo.evtch,
                    vtpminfo.rref, vtpminfo.backend);

              libxl_vtpminfo_dispose(&vtpminfo);
           }
           libxl_device_vtpm_dispose(&vtpms[i]);
        }
        free(vtpms);
    }
    return 0;
}

int main_vtpmdetach(int argc, char **argv)
{
    uint32_t domid;
    int opt, rc=0;
    libxl_device_vtpm vtpm;
    libxl_uuid uuid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vtpm-detach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);

    if ( libxl_uuid_from_string(&uuid, argv[optind+1])) {
        if (libxl_devid_to_device_vtpm(ctx, domid, atoi(argv[optind+1]), &vtpm)) {
            fprintf(stderr, "Unknown device %s.\n", argv[optind+1]);
            return 1;
        }
    } else {
        if (libxl_uuid_to_device_vtpm(ctx, domid, &uuid, &vtpm)) {
            fprintf(stderr, "Unknown device %s.\n", argv[optind+1]);
            return 1;
        }
    }
    rc = libxl_device_vtpm_remove(ctx, domid, &vtpm, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_vtpm_remove failed.\n");
    }
    libxl_device_vtpm_dispose(&vtpm);
    return rc;
}


static char *uptime_to_string(unsigned long uptime, int short_mode)
{
    int sec, min, hour, day;
    char *time_string;
    int ret;

    day = (int)(uptime / 86400);
    uptime -= (day * 86400);
    hour = (int)(uptime / 3600);
    uptime -= (hour * 3600);
    min = (int)(uptime / 60);
    uptime -= (min * 60);
    sec = uptime;

    if (short_mode)
        if (day > 1)
            ret = asprintf(&time_string, "%d days, %2d:%02d", day, hour, min);
        else if (day == 1)
            ret = asprintf(&time_string, "%d day, %2d:%02d", day, hour, min);
        else
            ret = asprintf(&time_string, "%2d:%02d", hour, min);
    else
        if (day > 1)
            ret = asprintf(&time_string, "%d days, %2d:%02d:%02d", day, hour, min, sec);
        else if (day == 1)
            ret = asprintf(&time_string, "%d day, %2d:%02d:%02d", day, hour, min, sec);
        else
            ret = asprintf(&time_string, "%2d:%02d:%02d", hour, min, sec);

    if (ret < 0)
        return NULL;
    return time_string;
}

int main_claims(int argc, char **argv)
{
    libxl_dominfo *info;
    int opt;
    int nb_domain;

    SWITCH_FOREACH_OPT(opt, "", NULL, "claims", 0) {
        /* No options */
    }

    if (!claim_mode)
        fprintf(stderr, "claim_mode not enabled (see man xl.conf).\n");

    info = libxl_list_domain(ctx, &nb_domain);
    if (!info) {
        fprintf(stderr, "libxl_list_domain failed.\n");
        return 1;
    }

    list_domains(0 /* verbose */, 0 /* context */, 1 /* claim */,
                 0 /* numa */, info, nb_domain);

    libxl_dominfo_list_free(info, nb_domain);
    return 0;
}

static char *current_time_to_string(time_t now)
{
    char now_str[100];
    struct tm *tmp;

    tmp = localtime(&now);
    if (tmp == NULL) {
        fprintf(stderr, "Get localtime error");
        exit(-1);
    }
    if (strftime(now_str, sizeof(now_str), "%H:%M:%S", tmp) == 0) {
        fprintf(stderr, "strftime returned 0");
        exit(-1);
    }
    return strdup(now_str);
}

static void print_dom0_uptime(int short_mode, time_t now)
{
    int fd;
    char buf[512];
    uint32_t uptime = 0;
    char *uptime_str = NULL;
    char *now_str = NULL;
    char *domname;

    fd = open("/proc/uptime", O_RDONLY);
    if (fd == -1)
        goto err;

    if (read(fd, buf, sizeof(buf)) == -1) {
        close(fd);
        goto err;
    }
    close(fd);

    strtok(buf, " ");
    uptime = strtoul(buf, NULL, 10);

    domname = libxl_domid_to_name(ctx, 0);
    if (short_mode)
    {
        now_str = current_time_to_string(now);
        uptime_str = uptime_to_string(uptime, 1);
        printf(" %s up %s, %s (%d)\n", now_str, uptime_str,
               domname, 0);
    }
    else
    {
        now_str = NULL;
        uptime_str = uptime_to_string(uptime, 0);
        printf("%-33s %4d %s\n", domname,
               0, uptime_str);
    }

    free(now_str);
    free(uptime_str);
    free(domname);
    return;
err:
    fprintf(stderr, "Can not get Dom0 uptime.\n");
    exit(-1);
}

static void print_domU_uptime(uint32_t domuid, int short_mode, time_t now)
{
    uint32_t s_time = 0;
    uint32_t uptime = 0;
    char *uptime_str = NULL;
    char *now_str = NULL;
    char *domname;

    s_time = libxl_vm_get_start_time(ctx, domuid);
    if (s_time == -1)
        return;
    uptime = now - s_time;
    domname = libxl_domid_to_name(ctx, domuid);
    if (short_mode)
    {
        now_str = current_time_to_string(now);
        uptime_str = uptime_to_string(uptime, 1);
        printf(" %s up %s, %s (%d)\n", now_str, uptime_str,
               domname, domuid);
    }
    else
    {
        now_str = NULL;
        uptime_str = uptime_to_string(uptime, 0);
        printf("%-33s %4d %s\n", domname,
               domuid, uptime_str);
    }

    free(domname);
    free(now_str);
    free(uptime_str);
    return;
}

static void print_uptime(int short_mode, uint32_t doms[], int nb_doms)
{
    libxl_vminfo *info;
    time_t now;
    int nb_vm, i;

    now = time(NULL);

    if (!short_mode)
        printf("%-33s %4s %s\n", "Name", "ID", "Uptime");

    if (nb_doms == 0) {
        print_dom0_uptime(short_mode, now);
        info = libxl_list_vm(ctx, &nb_vm);
        if (info == NULL) {
            fprintf(stderr, "Could not list vms.\n");
            return;
        }
        for (i = 0; i < nb_vm; i++)
            print_domU_uptime(info[i].domid, short_mode, now);
        libxl_vminfo_list_free(info, nb_vm);
    } else {
        for (i = 0; i < nb_doms; i++) {
            if (doms[i] == 0)
                print_dom0_uptime(short_mode, now);
            else
                print_domU_uptime(doms[i], short_mode, now);
        }
    }
}

int main_uptime(int argc, char **argv)
{
    const char *dom;
    int short_mode = 0;
    uint32_t domains[100];
    int nb_doms = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "s", NULL, "uptime", 0) {
    case 's':
        short_mode = 1;
        break;
    }

    for (;(dom = argv[optind]) != NULL; nb_doms++,optind++)
        domains[nb_doms] = find_domain(dom);

    print_uptime(short_mode, domains, nb_doms);

    return 0;
}

int main_tmem_list(int argc, char **argv)
{
    uint32_t domid;
    const char *dom = NULL;
    char *buf = NULL;
    int use_long = 0;
    int all = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "al", NULL, "tmem-list", 0) {
    case 'l':
        use_long = 1;
        break;
    case 'a':
        all = 1;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-list");
        return 1;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    buf = libxl_tmem_list(ctx, domid, use_long);
    if (buf == NULL)
        return -1;

    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main_tmem_freeze(int argc, char **argv)
{
    uint32_t domid;
    const char *dom = NULL;
    int all = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "a", NULL, "tmem-freeze", 0) {
    case 'a':
        all = 1;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-freeze");
        return 1;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    libxl_tmem_freeze(ctx, domid);
    return 0;
}

int main_tmem_thaw(int argc, char **argv)
{
    uint32_t domid;
    const char *dom = NULL;
    int all = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "a", NULL, "tmem-thaw", 0) {
    case 'a':
        all = 1;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-thaw");
        return 1;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    libxl_tmem_thaw(ctx, domid);
    return 0;
}

int main_tmem_set(int argc, char **argv)
{
    uint32_t domid;
    const char *dom = NULL;
    uint32_t weight = 0, cap = 0, compress = 0;
    int opt_w = 0, opt_c = 0, opt_p = 0;
    int all = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "aw:c:p:", NULL, "tmem-set", 0) {
    case 'a':
        all = 1;
        break;
    case 'w':
        weight = strtol(optarg, NULL, 10);
        opt_w = 1;
        break;
    case 'c':
        cap = strtol(optarg, NULL, 10);
        opt_c = 1;
        break;
    case 'p':
        compress = strtol(optarg, NULL, 10);
        opt_p = 1;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-set");
        return 1;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    if (!opt_w && !opt_c && !opt_p) {
        fprintf(stderr, "No set value specified.\n\n");
        help("tmem-set");
        return 1;
    }

    if (opt_w)
        libxl_tmem_set(ctx, domid, "weight", weight);
    if (opt_c)
        libxl_tmem_set(ctx, domid, "cap", cap);
    if (opt_p)
        libxl_tmem_set(ctx, domid, "compress", compress);

    return 0;
}

int main_tmem_shared_auth(int argc, char **argv)
{
    uint32_t domid;
    const char *autharg = NULL;
    char *endptr = NULL;
    const char *dom = NULL;
    char *uuid = NULL;
    int auth = -1;
    int all = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "au:A:", NULL, "tmem-shared-auth", 0) {
    case 'a':
        all = 1;
        break;
    case 'u':
        uuid = optarg;
        break;
    case 'A':
        autharg = optarg;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-shared-auth");
        return 1;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    if (uuid == NULL || autharg == NULL) {
        fprintf(stderr, "No uuid or auth specified.\n\n");
        help("tmem-shared-auth");
        return 1;
    }

    auth = strtol(autharg, &endptr, 10);
    if (*endptr != '\0') {
        fprintf(stderr, "Invalid auth, valid auth are <0|1>.\n\n");
        return 1;
    }

    libxl_tmem_shared_auth(ctx, domid, uuid, auth);

    return 0;
}

int main_tmem_freeable(int argc, char **argv)
{
    int opt;
    int mb;

    SWITCH_FOREACH_OPT(opt, "", NULL, "tmem-freeable", 0) {
        /* No options */
    }

    mb = libxl_tmem_freeable(ctx);
    if (mb == -1)
        return -1;

    printf("%d\n", mb);
    return 0;
}

int main_cpupoolcreate(int argc, char **argv)
{
    const char *filename = NULL, *config_src=NULL;
    const char *p;
    char extra_config[1024];
    int opt;
    static struct option opts[] = {
        {"defconfig", 1, 0, 'f'},
        {"dryrun", 0, 0, 'n'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };
    int ret;
    char *config_data = 0;
    int config_len = 0;
    XLU_Config *config;
    const char *buf;
    char *name = NULL;
    uint32_t poolid;
    libxl_scheduler sched = 0;
    XLU_ConfigList *cpus;
    XLU_ConfigList *nodes;
    int n_cpus, n_nodes, i, n;
    libxl_bitmap freemap;
    libxl_bitmap cpumap;
    libxl_uuid uuid;
    libxl_cputopology *topology;
    int rc = -ERROR_FAIL;

    SWITCH_FOREACH_OPT(opt, "hnf:", opts, "cpupool-create", 0) {
    case 'f':
        filename = optarg;
        break;
    case 'n':
        dryrun_only = 1;
        break;
    }

    memset(extra_config, 0, sizeof(extra_config));
    while (optind < argc) {
        if ((p = strchr(argv[optind], '='))) {
            if (strlen(extra_config) + 1 + strlen(argv[optind]) < sizeof(extra_config)) {
                strcat(extra_config, "\n");
                strcat(extra_config, argv[optind]);
            }
        } else if (!filename) {
            filename = argv[optind];
        } else {
            help("cpupool-create");
            goto out;
        }
        optind++;
    }

    if (filename)
    {
        if (libxl_read_file_contents(ctx, filename, (void **)&config_data,
                                     &config_len)) {
            fprintf(stderr, "Failed to read config file: %s: %s\n",
                    filename, strerror(errno));
            goto out;
        }
        config_src=filename;
    }
    else
        config_src="command line";

    if (strlen(extra_config)) {
        if (config_len > INT_MAX - (strlen(extra_config) + 2)) {
            fprintf(stderr, "Failed to attach extra configration\n");
            goto out;
        }
        config_data = xrealloc(config_data,
                               config_len + strlen(extra_config) + 2);
        if (!config_data) {
            fprintf(stderr, "Failed to realloc config_data\n");
            goto out;
        }
        config_data[config_len] = 0;
        strcat(config_data, extra_config);
        strcat(config_data, "\n");
        config_len += strlen(extra_config) + 1;
    }

    config = xlu_cfg_init(stderr, config_src);
    if (!config) {
        fprintf(stderr, "Failed to allocate for configuration\n");
        goto out;
    }

    ret = xlu_cfg_readdata(config, config_data, config_len);
    if (ret) {
        fprintf(stderr, "Failed to parse config file: %s\n", strerror(ret));
        goto out_cfg;
    }

    if (!xlu_cfg_get_string (config, "name", &buf, 0))
        name = strdup(buf);
    else if (filename)
        name = libxl_basename(filename);
    else {
        fprintf(stderr, "Missing cpupool name!\n");
        goto out_cfg;
    }
    if (!libxl_name_to_cpupoolid(ctx, name, &poolid)) {
        fprintf(stderr, "Pool name \"%s\" already exists\n", name);
        goto out_cfg;
    }

    if (!xlu_cfg_get_string (config, "sched", &buf, 0)) {
        if ((libxl_scheduler_from_string(buf, &sched)) < 0) {
            fprintf(stderr, "Unknown scheduler\n");
            goto out_cfg;
        }
    } else {
        if ((sched = libxl_get_scheduler(ctx)) < 0) {
            fprintf(stderr, "get_scheduler sysctl failed.\n");
            goto out_cfg;
        }
    }

    if (libxl_get_freecpus(ctx, &freemap)) {
        fprintf(stderr, "libxl_get_freecpus failed\n");
        goto out_cfg;
    }
    if (libxl_cpu_bitmap_alloc(ctx, &cpumap, 0)) {
        fprintf(stderr, "Failed to allocate cpumap\n");
        goto out_cfg;
    }
    if (!xlu_cfg_get_list(config, "nodes", &nodes, 0, 0)) {
        int nr;
        n_cpus = 0;
        n_nodes = 0;
        topology = libxl_get_cpu_topology(ctx, &nr);
        if (topology == NULL) {
            fprintf(stderr, "libxl_get_topologyinfo failed\n");
            goto out_cfg;
        }
        while ((buf = xlu_cfg_get_listitem(nodes, n_nodes)) != NULL) {
            n = atoi(buf);
            for (i = 0; i < nr; i++) {
                if ((topology[i].node == n) &&
                    libxl_bitmap_test(&freemap, i)) {
                    libxl_bitmap_set(&cpumap, i);
                    n_cpus++;
                }
            }
            n_nodes++;
        }

        libxl_cputopology_list_free(topology, nr);

        if (n_cpus == 0) {
            fprintf(stderr, "no free cpu found\n");
            goto out_cfg;
        }
    } else if (!xlu_cfg_get_list(config, "cpus", &cpus, 0, 0)) {
        n_cpus = 0;
        while ((buf = xlu_cfg_get_listitem(cpus, n_cpus)) != NULL) {
            i = atoi(buf);
            if ((i < 0) || (i >= freemap.size * 8) ||
                !libxl_bitmap_test(&freemap, i)) {
                fprintf(stderr, "cpu %d illegal or not free\n", i);
                goto out_cfg;
            }
            libxl_bitmap_set(&cpumap, i);
            n_cpus++;
        }
    } else
        n_cpus = 0;

    libxl_uuid_generate(&uuid);

    printf("Using config file \"%s\"\n", config_src);
    printf("cpupool name:   %s\n", name);
    printf("scheduler:      %s\n", libxl_scheduler_to_string(sched));
    printf("number of cpus: %d\n", n_cpus);

    if (!dryrun_only) {
        poolid = 0;
        if (libxl_cpupool_create(ctx, name, sched, cpumap, &uuid, &poolid)) {
            fprintf(stderr, "error on creating cpupool\n");
            goto out_cfg;
        }
    }
    /* We made it! */
    rc = 0;
   
out_cfg:
    xlu_cfg_destroy(config);
out:
    free(name);
    free(config_data);
    return rc;
}

int main_cpupoollist(int argc, char **argv)
{
    int opt;
    static struct option opts[] = {
        {"cpus", 0, 0, 'c'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };
    int opt_cpus = 0;
    const char *pool = NULL;
    libxl_cpupoolinfo *poolinfo;
    int n_pools, p, c, n;
    uint32_t poolid;
    char *name;
    int ret = 0;

    SWITCH_FOREACH_OPT(opt, "hc", opts, "cpupool-list", 0) {
    case 'c':
        opt_cpus = 1;
        break;
    }

    if (optind < argc) {
        pool = argv[optind];
        if (libxl_name_to_cpupoolid(ctx, pool, &poolid)) {
            fprintf(stderr, "Pool \'%s\' does not exist\n", pool);
            return -ERROR_FAIL;
        }
    }

    poolinfo = libxl_list_cpupool(ctx, &n_pools);
    if (!poolinfo) {
        fprintf(stderr, "error getting cpupool info\n");
        return -ERROR_NOMEM;
    }

    printf("%-19s", "Name");
    if (opt_cpus)
        printf("CPU list\n");
    else
        printf("CPUs   Sched     Active   Domain count\n");

    for (p = 0; p < n_pools; p++) {
        if (!ret && (!pool || (poolinfo[p].poolid == poolid))) {
            name = poolinfo[p].pool_name;
            printf("%-19s", name);
            n = 0;
            libxl_for_each_bit(c, poolinfo[p].cpumap)
                if (libxl_bitmap_test(&poolinfo[p].cpumap, c)) {
                    if (n && opt_cpus) printf(",");
                    if (opt_cpus) printf("%d", c);
                    n++;
                }
            if (!opt_cpus) {
                printf("%3d %9s       y       %4d", n,
                       libxl_scheduler_to_string(poolinfo[p].sched),
                       poolinfo[p].n_dom);
            }
            printf("\n");
        }
    }

    libxl_cpupoolinfo_list_free(poolinfo, n_pools);

    return ret;
}

int main_cpupooldestroy(int argc, char **argv)
{
    int opt;
    const char *pool;
    uint32_t poolid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-destroy", 1) {
        /* No options */
    }

    pool = argv[optind];

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool \'%s\'\n", pool);
        return -ERROR_FAIL;
    }

    return -libxl_cpupool_destroy(ctx, poolid);
}

int main_cpupoolrename(int argc, char **argv)
{
    int opt;
    const char *pool;
    const char *new_name;
    uint32_t poolid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-rename", 2) {
        /* No options */
    }

    pool = argv[optind++];

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool \'%s\'\n", pool);
        return -ERROR_FAIL;
    }

    new_name = argv[optind];

    if (libxl_cpupool_rename(ctx, new_name, poolid)) {
        fprintf(stderr, "Can't rename cpupool '%s'.\n", pool);
        return 1;
    }

    return 0;
}

int main_cpupoolcpuadd(int argc, char **argv)
{
    int opt;
    const char *pool;
    uint32_t poolid;
    int cpu;
    int node;
    int n;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-cpu-add", 2) {
        /* No options */
    }

    pool = argv[optind++];
    node = -1;
    cpu = -1;
    if (strncmp(argv[optind], "node:", 5) == 0) {
        node = atoi(argv[optind] + 5);
    } else {
        cpu = atoi(argv[optind]);
    }

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool \'%s\'\n", pool);
        return -ERROR_FAIL;
    }

    if (cpu >= 0) {
        return -libxl_cpupool_cpuadd(ctx, poolid, cpu);
    }

    if (libxl_cpupool_cpuadd_node(ctx, poolid, node, &n)) {
        fprintf(stderr, "libxl_cpupool_cpuadd_node failed\n");
        return -ERROR_FAIL;
    }

    if (n > 0) {
        return 0;
    }

    fprintf(stderr, "no free cpu found\n");
    return -ERROR_FAIL;
}

int main_cpupoolcpuremove(int argc, char **argv)
{
    int opt;
    const char *pool;
    uint32_t poolid;
    int cpu;
    int node;
    int n;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-cpu-remove", 2) {
        /* No options */
    }

    pool = argv[optind++];
    node = -1;
    cpu = -1;
    if (strncmp(argv[optind], "node:", 5) == 0) {
        node = atoi(argv[optind] + 5);
    } else {
        cpu = atoi(argv[optind]);
    }

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool \'%s\'\n", pool);
        return -ERROR_FAIL;
    }

    if (cpu >= 0) {
        return -libxl_cpupool_cpuremove(ctx, poolid, cpu);
    }

    if (libxl_cpupool_cpuremove_node(ctx, poolid, node, &n)) {
        fprintf(stderr, "libxl_cpupool_cpuremove_node failed\n");
        return -ERROR_FAIL;
    }

    if (n == 0) {
        fprintf(stderr, "no cpu of node found in cpupool\n");
        return -ERROR_FAIL;
    }

    return 0;
}

int main_cpupoolmigrate(int argc, char **argv)
{
    int opt;
    const char *pool;
    uint32_t poolid;
    const char *dom;
    uint32_t domid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-migrate", 2) {
        /* No options */
    }

    dom = argv[optind++];
    pool = argv[optind];

    if (libxl_domain_qualifier_to_domid(ctx, dom, &domid) ||
        !libxl_domid_to_name(ctx, domid)) {
        fprintf(stderr, "unknown domain \'%s\'\n", dom);
        return -ERROR_FAIL;
    }

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool \'%s\'\n", pool);
        return -ERROR_FAIL;
    }

    return -libxl_cpupool_movedomain(ctx, poolid, domid);
}

int main_cpupoolnumasplit(int argc, char **argv)
{
    int ret;
    int opt;
    int p;
    int c;
    int n;
    uint32_t poolid;
    libxl_scheduler sched;
    int n_pools;
    int node;
    int n_cpus;
    char name[16];
    libxl_uuid uuid;
    libxl_bitmap cpumap;
    libxl_cpupoolinfo *poolinfo;
    libxl_cputopology *topology;
    libxl_dominfo info;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-numa-split", 0) {
        /* No options */
    }

    ret = 0;

    poolinfo = libxl_list_cpupool(ctx, &n_pools);
    if (!poolinfo) {
        fprintf(stderr, "error getting cpupool info\n");
        return -ERROR_NOMEM;
    }
    poolid = poolinfo[0].poolid;
    sched = poolinfo[0].sched;
    for (p = 0; p < n_pools; p++) {
        libxl_cpupoolinfo_dispose(poolinfo + p);
    }
    if (n_pools > 1) {
        fprintf(stderr, "splitting not possible, already cpupools in use\n");
        return -ERROR_FAIL;
    }

    topology = libxl_get_cpu_topology(ctx, &n_cpus);
    if (topology == NULL) {
        fprintf(stderr, "libxl_get_topologyinfo failed\n");
        return -ERROR_FAIL;
    }

    if (libxl_cpu_bitmap_alloc(ctx, &cpumap, 0)) {
        fprintf(stderr, "Failed to allocate cpumap\n");
        libxl_cputopology_list_free(topology, n_cpus);
        return -ERROR_FAIL;
    }

    /* Reset Pool-0 to 1st node: first add cpus, then remove cpus to avoid
       a cpupool without cpus in between */

    node = topology[0].node;
    if (libxl_cpupool_cpuadd_node(ctx, 0, node, &n)) {
        fprintf(stderr, "error on adding cpu to Pool 0\n");
        return -ERROR_FAIL;
    }

    snprintf(name, 15, "Pool-node%d", node);
    ret = -libxl_cpupool_rename(ctx, name, 0);
    if (ret) {
        fprintf(stderr, "error on renaming Pool 0\n");
        goto out;
    }

    n = 0;
    for (c = 0; c < n_cpus; c++) {
        if (topology[c].node == node) {
            topology[c].node = LIBXL_CPUTOPOLOGY_INVALID_ENTRY;
            libxl_bitmap_set(&cpumap, n);
            n++;
        }
    }
    if (libxl_set_vcpuonline(ctx, 0, &cpumap)) {
        fprintf(stderr, "error on removing vcpus for Domain-0\n");
        goto out;
    }
    for (c = 0; c < 10; c++) {
        if (libxl_domain_info(ctx, &info, 0)) {
            fprintf(stderr, "error on getting info for Domain-0\n");
            goto out;
        }
        if (info.vcpu_online == n) {
            break;
        }
        sleep(1);
    }
    if (info.vcpu_online > n) {
        fprintf(stderr, "failed to offline vcpus\n");
        goto out;
    }
    libxl_bitmap_set_none(&cpumap);

    for (c = 0; c < n_cpus; c++) {
        if (topology[c].node == LIBXL_CPUTOPOLOGY_INVALID_ENTRY) {
            continue;
        }

        node = topology[c].node;
        ret = -libxl_cpupool_cpuremove_node(ctx, 0, node, &n);
        if (ret) {
            fprintf(stderr, "error on removing cpu from Pool 0\n");
            goto out;
        }

        snprintf(name, 15, "Pool-node%d", node);
        libxl_uuid_generate(&uuid);
        poolid = 0;
        ret = -libxl_cpupool_create(ctx, name, sched, cpumap, &uuid, &poolid);
        if (ret) {
            fprintf(stderr, "error on creating cpupool\n");
            goto out;
        }

        ret = -libxl_cpupool_cpuadd_node(ctx, poolid, node, &n);
        if (ret) {
            fprintf(stderr, "error on adding cpus to cpupool\n");
            goto out;
        }

        for (p = c; p < n_cpus; p++) {
            if (topology[p].node == node) {
                topology[p].node = LIBXL_CPUTOPOLOGY_INVALID_ENTRY;
            }
        }
    }

out:
    libxl_cputopology_list_free(topology, n_cpus);
    libxl_bitmap_dispose(&cpumap);

    return ret;
}

int main_getenforce(int argc, char **argv)
{
    int ret;

    ret = libxl_flask_getenforce(ctx);

    if (ret < 0) {
        if (errno == ENOSYS)
            printf("Flask XSM Disabled\n");
        else
            fprintf(stderr, "Failed to get enforcing mode\n");
    }
    else if (ret == 1)
        printf("Enforcing\n");
    else if (ret == 0)
        printf("Permissive\n");

    return ret;
}

int main_setenforce(int argc, char **argv)
{
    int ret, mode = -1;
    const char *p = NULL;

    if (optind >= argc) {
        help("setenforce");
        return 2;
    }

    p = argv[optind];

    if (!strcmp(p, "0"))
        mode = 0;
    else if (!strcmp(p, "1"))
        mode = 1;
    else if (!strcasecmp(p, "permissive"))
        mode = 0;
    else if (!strcasecmp(p, "enforcing"))
        mode = 1;
    else {
        help("setenforce");
        return 2;
    }

    ret = libxl_flask_setenforce(ctx, mode);

    if (ret) {
        if (errno == ENOSYS) {
            fprintf(stderr, "Flask XSM disabled\n");
        }
        else
            fprintf(stderr, "error occured while setting enforcing mode (%i)\n", ret);
    }

    return ret;
}

int main_loadpolicy(int argc, char **argv)
{
    const char *polFName;
    int polFd = 0;
    void *polMemCp = NULL;
    struct stat info;
    int ret;

    if (optind >= argc) {
        help("loadpolicy");
        return 2;
    }

    polFName = argv[optind];
    polFd = open(polFName, O_RDONLY);
    if ( polFd < 0 ) {
        fprintf(stderr, "Error occurred opening policy file '%s': %s\n",
                polFName, strerror(errno));
        ret = -1;
        goto done;
    }

    ret = stat(polFName, &info);
    if ( ret < 0 ) {
        fprintf(stderr, "Error occurred retrieving information about"
                "policy file '%s': %s\n", polFName, strerror(errno));
        goto done;
    }

    polMemCp = malloc(info.st_size);

    ret = read(polFd, polMemCp, info.st_size);
    if ( ret < 0 ) {
        fprintf(stderr, "Unable to read new Flask policy file: %s\n",
                strerror(errno));
        goto done;
    }

    ret = libxl_flask_loadpolicy(ctx, polMemCp, info.st_size);

    if (ret < 0) {
        if (errno == ENOSYS) {
            fprintf(stderr, "Flask XSM disabled\n");
        } else {
            errno = -ret;
            fprintf(stderr, "Unable to load new Flask policy: %s\n",
                    strerror(errno));
            ret = -1;
        }
    } else {
        printf("Successfully loaded policy.\n");
    }

done:
    free(polMemCp);
    if ( polFd > 0 )
        close(polFd);

    return ret;
}

#ifndef LIBXL_HAVE_NO_SUSPEND_RESUME
int main_remus(int argc, char **argv)
{
    uint32_t domid;
    int opt, rc, daemonize = 1;
    const char *ssh_command = "ssh";
    char *host = NULL, *rune = NULL;
    libxl_domain_remus_info r_info;
    int send_fd = -1, recv_fd = -1;
    pid_t child = -1;
    uint8_t *config_data;
    int config_len;

    memset(&r_info, 0, sizeof(libxl_domain_remus_info));
    /* Defaults */
    r_info.interval = 200;
    libxl_defbool_setdefault(&r_info.blackhole, false);

    SWITCH_FOREACH_OPT(opt, "Fbundi:s:N:e", NULL, "remus", 2) {
    case 'i':
        r_info.interval = atoi(optarg);
        break;
    case 'F':
        libxl_defbool_set(&r_info.allow_unsafe, true);
        break;
    case 'b':
        libxl_defbool_set(&r_info.blackhole, true);
        break;
    case 'u':
        libxl_defbool_set(&r_info.compression, false);
        break;
    case 'n':
        libxl_defbool_set(&r_info.netbuf, false);
        break;
    case 'N':
        r_info.netbufscript = optarg;
        break;
    case 'd':
        libxl_defbool_set(&r_info.diskbuf, false);
        break;
    case 's':
        ssh_command = optarg;
        break;
    case 'e':
        daemonize = 0;
        break;
    }

    domid = find_domain(argv[optind]);
    host = argv[optind + 1];

    if (!r_info.netbufscript)
        r_info.netbufscript = default_remus_netbufscript;

    if (libxl_defbool_val(r_info.blackhole)) {
        send_fd = open("/dev/null", O_RDWR, 0644);
        if (send_fd < 0) {
            perror("failed to open /dev/null");
            exit(-1);
        }
    } else {

        if (!ssh_command[0]) {
            rune = host;
        } else {
            if (asprintf(&rune, "exec %s %s xl migrate-receive -r %s",
                         ssh_command, host,
                         daemonize ? "" : " -e") < 0)
                return 1;
        }

        save_domain_core_begin(domid, NULL, &config_data, &config_len);

        if (!config_len) {
            fprintf(stderr, "No config file stored for running domain and "
                    "none supplied - cannot start remus.\n");
            exit(1);
        }

        child = create_migration_child(rune, &send_fd, &recv_fd);

        migrate_do_preamble(send_fd, recv_fd, child, config_data, config_len,
                            rune);

        if (ssh_command[0])
            free(rune);
    }

    /* Point of no return */
    rc = libxl_domain_remus_start(ctx, &r_info, domid, send_fd, recv_fd, 0);

    /* check if the domain exists. User may have xl destroyed the
     * domain to force failover
     */
    if (libxl_domain_info(ctx, 0, domid)) {
        fprintf(stderr, "Remus: Primary domain has been destroyed.\n");
        close(send_fd);
        return 0;
    }

    /* If we are here, it means remus setup/domain suspend/backup has
     * failed. Try to resume the domain and exit gracefully.
     * TODO: Split-Brain check.
     */
    if (rc == ERROR_GUEST_TIMEDOUT)
        fprintf(stderr, "Failed to suspend domain at primary.\n");
    else {
        fprintf(stderr, "Remus: Backup failed? resuming domain at primary.\n");
        libxl_domain_resume(ctx, domid, 1, 0);
    }

    close(send_fd);
    return -ERROR_FAIL;
}
#endif

int main_devd(int argc, char **argv)
{
    int ret = 0, opt = 0, daemonize = 1;

    SWITCH_FOREACH_OPT(opt, "F", NULL, "devd", 0) {
    case 'F':
        daemonize = 0;
        break;
    }

    if (daemonize) {
        ret = do_daemonize("xldevd");
        if (ret) {
            ret = (ret == 1) ? 0 : ret;
            goto out;
        }
    }

    libxl_device_events_handler(ctx, 0);

out:
    return ret;
}

#ifdef LIBXL_HAVE_PSR_CMT
static void psr_cmt_print_domain_cache_occupancy(libxl_dominfo *dominfo,
                                                    uint32_t nr_sockets)
{
    char *domain_name;
    uint32_t socketid;
    uint32_t l3_cache_occupancy;

    if (!libxl_psr_cmt_domain_attached(ctx, dominfo->domid))
        return;

    domain_name = libxl_domid_to_name(ctx, dominfo->domid);
    printf("%-40s %5d", domain_name, dominfo->domid);
    free(domain_name);

    for (socketid = 0; socketid < nr_sockets; socketid++) {
        if ( !libxl_psr_cmt_get_cache_occupancy(ctx, dominfo->domid,
                 socketid, &l3_cache_occupancy) )
            printf("%13u KB", l3_cache_occupancy);
    }

    printf("\n");
}

static int psr_cmt_show_cache_occupancy(uint32_t domid)
{
    uint32_t i, socketid, nr_sockets, total_rmid;
    uint32_t l3_cache_size;
    libxl_physinfo info;
    int rc, nr_domains;

    if (!libxl_psr_cmt_enabled(ctx)) {
        fprintf(stderr, "CMT is disabled in the system\n");
        return -1;
    }

    libxl_physinfo_init(&info);
    rc = libxl_get_physinfo(ctx, &info);
    if (rc < 0) {
        fprintf(stderr, "Failed getting physinfo, rc: %d\n", rc);
        libxl_physinfo_dispose(&info);
        return -1;
    }
    nr_sockets = info.nr_cpus / info.threads_per_core / info.cores_per_socket;
    libxl_physinfo_dispose(&info);

    rc = libxl_psr_cmt_get_total_rmid(ctx, &total_rmid);
    if (rc < 0) {
        fprintf(stderr, "Failed to get max RMID value\n");
        return -1;
    }

    printf("Total RMID: %d\n", total_rmid);

    /* Header */
    printf("%-40s %5s", "Name", "ID");
    for (socketid = 0; socketid < nr_sockets; socketid++)
        printf("%14s %d", "Socket", socketid);
    printf("\n");

    /* Total L3 cache size */
    printf("%-46s", "Total L3 Cache Size");
    for (socketid = 0; socketid < nr_sockets; socketid++) {
        rc = libxl_psr_cmt_get_l3_cache_size(ctx, socketid, &l3_cache_size);
        if (rc < 0) {
            fprintf(stderr, "Failed to get system l3 cache size for socket:%d\n",
                            socketid);
            return -1;
        }
        printf("%13u KB", l3_cache_size);
    }
    printf("\n");

    /* Each domain */
    if (domid != INVALID_DOMID) {
        libxl_dominfo dominfo;
        if (libxl_domain_info(ctx, &dominfo, domid)) {
            fprintf(stderr, "Failed to get domain info for %d\n", domid);
            return -1;
        }
        psr_cmt_print_domain_cache_occupancy(&dominfo, nr_sockets);
    }
    else
    {
        libxl_dominfo *list;
        if (!(list = libxl_list_domain(ctx, &nr_domains))) {
            fprintf(stderr, "Failed to get domain info for domain list.\n");
            return -1;
        }
        for (i = 0; i < nr_domains; i++)
            psr_cmt_print_domain_cache_occupancy(list + i, nr_sockets);
        libxl_dominfo_list_free(list, nr_domains);
    }
    return 0;
}

int main_psr_cmt_attach(int argc, char **argv)
{
    uint32_t domid;
    int opt, ret = 0;

    SWITCH_FOREACH_OPT(opt, "", NULL, "psr-cmt-attach", 1) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    ret = libxl_psr_cmt_attach(ctx, domid);

    return ret;
}

int main_psr_cmt_detach(int argc, char **argv)
{
    uint32_t domid;
    int opt, ret = 0;

    SWITCH_FOREACH_OPT(opt, "", NULL, "psr-cmt-detach", 1) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    ret = libxl_psr_cmt_detach(ctx, domid);

    return ret;
}

int main_psr_cmt_show(int argc, char **argv)
{
    int opt, ret = 0;
    uint32_t domid;
    libxl_psr_cmt_type type;

    SWITCH_FOREACH_OPT(opt, "", NULL, "psr-cmt-show", 1) {
        /* No options */
    }

    libxl_psr_cmt_type_from_string(argv[optind], &type);

    if (optind + 1 >= argc)
        domid = INVALID_DOMID;
    else if (optind + 1 == argc - 1)
        domid = find_domain(argv[optind + 1]);
    else {
        help("psr-cmt-show");
        return 2;
    }

    switch (type) {
    case LIBXL_PSR_CMT_TYPE_CACHE_OCCUPANCY:
        ret = psr_cmt_show_cache_occupancy(domid);
        break;
    default:
        help("psr-cmt-show");
        return 2;
    }

    return ret;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
