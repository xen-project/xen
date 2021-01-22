#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <xenctrl.h>
#include <xenguest.h>

#include "xenstore.h"

/* Add a string plus terminating 0 byte to buf, returning new len. */
static int add_to_buf(char **buf, const char *val, int len)
{
    int vallen = strlen(val) + 1;

    if (len < 0)
        return -1;

    *buf = realloc(*buf, len + vallen);
    if (!*buf)
        return -1;

    strcpy(*buf + len, val);

    return len + vallen;
}

static int live_update_start(struct xs_handle *xsh, bool force, unsigned int to)
{
    int len = 0;
    char *buf = NULL, *ret;
    time_t time_start;

    if (asprintf(&ret, "%u", to) < 0)
        return 1;
    len = add_to_buf(&buf, "-s", len);
    len = add_to_buf(&buf, "-t", len);
    len = add_to_buf(&buf, ret, len);
    free(ret);
    if (force)
        len = add_to_buf(&buf, "-F", len);
    if (len < 0)
        return 1;

    for (time_start = time(NULL); time(NULL) - time_start < to;) {
        ret = xs_control_command(xsh, "live-update", buf, len);
        if (!ret)
            goto err;
        if (strcmp(ret, "BUSY"))
            break;
        sleep(1);
    }

    if (strcmp(ret, "OK"))
        goto err;

    free(buf);
    free(ret);

    return 0;

 err:
    fprintf(stderr, "Starting live update failed:\n%s\n",
            ret ? : strerror(errno));
    free(buf);
    free(ret);

    return 3;
}

static int live_update_cmdline(struct xs_handle *xsh, const char *cmdline)
{
    int len = 0, rc = 0;
    char *buf = NULL, *ret;

    len = add_to_buf(&buf, "-c", len);
    len = add_to_buf(&buf, cmdline, len);
    if (len < 0)
        return 1;

    ret = xs_control_command(xsh, "live-update", buf, len);
    free(buf);
    if (!ret || strcmp(ret, "OK")) {
        fprintf(stderr, "Setting update binary failed:\n%s\n",
                ret ? : strerror(errno));
        rc = 3;
    }
    free(ret);

    return rc;
}

static int send_kernel_blob(struct xs_handle *xsh, const char *binary)
{
    int rc = 0, len = 0;
    xc_interface *xch;
    struct xc_dom_image *dom;
    char *ret, *buf = NULL;
    size_t off, sz;
#define BLOB_CHUNK_SZ 2048

    xch = xc_interface_open(NULL, NULL, 0);
    if (!xch) {
        fprintf(stderr, "xc_interface_open() failed\n");
        return 1;
    }

    dom = xc_dom_allocate(xch, NULL, NULL);
    if (!dom) {
        rc = 1;
        goto out_close;
    }

    rc = xc_dom_kernel_file(dom, binary);
    if (rc) {
        rc = 1;
        goto out_rel;
    }

    if (asprintf(&ret, "%zu", dom->kernel_size) < 0) {
        rc = 1;
        goto out_rel;
    }
    len = add_to_buf(&buf, "-b", len);
    len = add_to_buf(&buf, ret, len);
    free(ret);
    if (len < 0) {
        rc = 1;
        goto out_rel;
    }
    ret = xs_control_command(xsh, "live-update", buf, len);
    free(buf);
    if (!ret || strcmp(ret, "OK")) {
        fprintf(stderr, "Starting live update failed:\n%s\n",
                ret ? : strerror(errno));
        rc = 3;
    }
    free(ret);
    if (rc)
        goto out_rel;

    /* buf capable to hold "-d" <1..2048> BLOB_CHUNK_SZ and a terminating 0. */
    buf = malloc(3 + 5 + BLOB_CHUNK_SZ + 1);
    if (!buf) {
        rc = 1;
        goto out_rel;
    }

    strcpy(buf, "-d");
    sz = BLOB_CHUNK_SZ;
    for (off = 0; off < dom->kernel_size; off += BLOB_CHUNK_SZ) {
        if (dom->kernel_size - off < BLOB_CHUNK_SZ)
            sz = dom->kernel_size - off;
        sprintf(buf + 3, "%zu", sz);
        len = 3 + strlen(buf + 3) + 1;
        memcpy(buf + len, dom->kernel_blob + off, sz);
        buf[len + sz] = 0;
        len += sz + 1;
        ret = xs_control_command(xsh, "live-update", buf, len);
        if (!ret || strcmp(ret, "OK")) {
            fprintf(stderr, "Transfer of new binary failed:\n%s\n",
                    ret ? : strerror(errno));
            rc = 3;
            free(ret);
            break;
        }
        free(ret);
    }

    free(buf);

 out_rel:
    xc_dom_release(dom);

 out_close:
    xc_interface_close(xch);

    return rc;
}

/*
 * Live update of Xenstore stubdom
 *
 * Sequence of actions:
 * 1. transfer new stubdom binary
 *    a) specify size
 *    b) transfer unpacked binary in chunks
 * 2. transfer new cmdline (optional)
 * 3. start update (includes flags)
 */
static int live_update_stubdom(struct xs_handle *xsh, const char *binary,
                               const char *cmdline, bool force, unsigned int to)
{
    int rc;

    rc = send_kernel_blob(xsh, binary);
    if (rc)
        goto abort;

    if (cmdline) {
        rc = live_update_cmdline(xsh, cmdline);
        if (rc)
            goto abort;
    }

    rc = live_update_start(xsh, force, to);
    if (rc)
        goto abort;

    return 0;

 abort:
    xs_control_command(xsh, "live-update", "-a", 3);
    return rc;
}

/*
 * Live update of Xenstore daemon
 *
 * Sequence of actions:
 * 1. transfer new binary filename
 * 2. transfer new cmdline (optional)
 * 3. start update (includes flags)
 */
static int live_update_daemon(struct xs_handle *xsh, const char *binary,
                              const char *cmdline, bool force, unsigned int to)
{
    int len = 0, rc;
    char *buf = NULL, *ret;

    len = add_to_buf(&buf, "-f", len);
    len = add_to_buf(&buf, binary, len);
    if (len < 0)
        return 1;
    ret = xs_control_command(xsh, "live-update", buf, len);
    free(buf);
    if (!ret || strcmp(ret, "OK")) {
        fprintf(stderr, "Setting update binary failed:\n%s\n",
                ret ? : strerror(errno));
        free(ret);
        return 3;
    }
    free(ret);

    if (cmdline) {
        rc = live_update_cmdline(xsh, cmdline);
        if (rc)
            goto abort;
    }

    rc = live_update_start(xsh, force, to);
    if (rc)
        goto abort;

    return 0;

 abort:
    xs_control_command(xsh, "live-update", "-a", 3);
    return rc;
}

static int live_update(struct xs_handle *xsh, int argc, char **argv)
{
    int rc = 0;
    unsigned int i, to = 60;
    char *binary = NULL, *cmdline = NULL, *val;
    bool force = false;

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-c")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing command line value\n");
                rc = 2;
                goto out;
            }
            cmdline = argv[i];
        } else if (!strcmp(argv[i], "-t")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing timeout value\n");
                rc = 2;
                goto out;
            }
            to = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-F"))
            force = true;
        else
            binary = argv[i];
    }

    if (!binary) {
        fprintf(stderr, "Missing binary specification\n");
        rc = 2;
        goto out;
    }

    val = xs_read(xsh, XBT_NULL, "/tool/xenstored/domid", &i);
    if (val)
        rc = live_update_stubdom(xsh, binary, cmdline, force, to);
    else
        rc = live_update_daemon(xsh, binary, cmdline, force, to);

    free(val);

 out:
    return rc;
}

int main(int argc, char **argv)
{
    struct xs_handle *xsh;
    char *par = NULL;
    char *ret;
    unsigned int p;
    int rc = 0, len = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage:\n"
                "%s <command> [<arg>...]\n", argv[0]);
        rc = 2;
        goto out;
    }

    xsh = xs_open(0);
    if (xsh == NULL) {
        fprintf(stderr, "Failed to contact Xenstored.\n");
        rc = 1;
        goto out;
    }

    if (!strcmp(argv[1], "live-update")) {
        rc = live_update(xsh, argc - 2, argv + 2);
        goto out_close;
    }

    for (p = 2; p < argc; p++)
        len = add_to_buf(&par, argv[p], len);
    if (len < 0) {
        fprintf(stderr, "Allocation error.\n");
        rc = 1;
        goto out_close;
    }

    ret = xs_control_command(xsh, argv[1], par, len);
    if (!ret) {
        rc = 3;
        if (errno == EINVAL) {
            ret = xs_control_command(xsh, "help", NULL, 0);
            if (ret)
                fprintf(stderr, "Command not supported. Valid commands are:\n"
                                "%s\n", ret);
            else
                fprintf(stderr, "Error when executing command.\n");
        } else
            fprintf(stderr, "Error %d when trying to execute command.\n",
                    errno);
    } else if (strlen(ret) > 0)
        printf("%s\n", ret);

 out_close:
    xs_close(xsh);

 out:
    free(par);
    return rc;
}
