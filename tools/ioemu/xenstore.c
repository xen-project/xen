/*
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2006 Christian Limpach
 * Copyright (C) 2006 XenSource Ltd.
 *
 */

#include "vl.h"
#include "block_int.h"

static struct xs_handle *xsh = NULL;
static char *hd_filename[MAX_DISKS];
static QEMUTimer *insert_timer = NULL;

static int pasprintf(char **buf, const char *fmt, ...)
{
    va_list ap;
    int ret = 0;

    if (*buf)
	free(*buf);
    va_start(ap, fmt);
    if (vasprintf(buf, fmt, ap) == -1) {
	buf = NULL;
	ret = -1;
    }
    va_end(ap);
    return ret;
}

static void insert_media(void *opaque)
{
    int i;

    for (i = 0; i < MAX_DISKS; i++) {
	if (hd_filename[i]) {
	    do_change(bs_table[i]->device_name, hd_filename[i]);
	    free(hd_filename[i]);
	    hd_filename[i] = NULL;
	}
    }
}

void xenstore_check_new_media_present(int timeout)
{

    if (insert_timer == NULL)
	insert_timer = qemu_new_timer(rt_clock, insert_media, NULL);
    qemu_mod_timer(insert_timer, qemu_get_clock(rt_clock) + timeout);
}

void xenstore_parse_domain_config(int domid)
{
    char **e = NULL;
    char *buf = NULL, *path;
    char *bpath = NULL, *dev = NULL, *params = NULL, *type = NULL;
    int i;
    unsigned int len, num, hd_index;

    for(i = 0; i < MAX_DISKS; i++)
        hd_filename[i] = NULL;

    xsh = xs_daemon_open();
    if (xsh == NULL) {
	fprintf(logfile, "Could not contact xenstore for domain config\n");
	return;
    }

    path = xs_get_domain_path(xsh, domid);
    if (path == NULL) {
        fprintf(logfile, "xs_get_domain_path() error\n");
        goto out;
    }

    if (pasprintf(&buf, "%s/device/vbd", path) == -1)
	goto out;

    e = xs_directory(xsh, XBT_NULL, buf, &num);
    if (e == NULL)
	goto out;

    for (i = 0; i < num; i++) {
	/* read the backend path */
	if (pasprintf(&buf, "%s/device/vbd/%s/backend", path, e[i]) == -1)
	    continue;
	free(bpath);
        bpath = xs_read(xsh, XBT_NULL, buf, &len);
	if (bpath == NULL)
	    continue;
	/* read the name of the device */
	if (pasprintf(&buf, "%s/dev", bpath) == -1)
	    continue;
	free(dev);
	dev = xs_read(xsh, XBT_NULL, buf, &len);
	if (dev == NULL)
	    continue;
	if (strncmp(dev, "hd", 2) || strlen(dev) != 3)
	    continue;
	hd_index = dev[2] - 'a';
	if (hd_index > MAX_DISKS)
	    continue;
	/* read the type of the device */
	if (pasprintf(&buf, "%s/device/vbd/%s/device-type", path, e[i]) == -1)
	    continue;
	free(type);
	type = xs_read(xsh, XBT_NULL, buf, &len);
	/* read params to get the patch of the image -- read it last
	 * so that we have its path in buf when setting up the
	 * watch */
	if (pasprintf(&buf, "%s/params", bpath) == -1)
	    continue;
	free(params);
	params = xs_read(xsh, XBT_NULL, buf, &len);
	if (params == NULL)
	    continue;
	if (params[0]) {
	    hd_filename[hd_index] = params;	/* strdup() */
	    params = NULL;		/* don't free params on re-use */
	}
	bs_table[hd_index] = bdrv_new(dev);
	/* check if it is a cdrom */
	if (type && !strcmp(type, "cdrom")) {
	    bdrv_set_type_hint(bs_table[hd_index], BDRV_TYPE_CDROM);
	    xs_watch(xsh, buf, dev);
	}
	if (hd_filename[hd_index]) {
            if (bdrv_open(bs_table[hd_index], hd_filename[hd_index],
			  0 /* snapshot */) < 0)
                fprintf(stderr, "qemu: could not open hard disk image '%s'\n",
                        hd_filename[hd_index]);
	}
    }

 out:
    free(type);
    free(params);
    free(dev);
    free(bpath);
    free(buf);
    free(path);
    free(e);
    return;
}

int xenstore_fd(void)
{
    if (xsh)
	return xs_fileno(xsh);
    return -1;
}

void xenstore_process_event(void *opaque)
{
    char **vec, *image = NULL;
    unsigned int len, num, hd_index;

    vec = xs_read_watch(xsh, &num);
    if (!vec)
	return;

    if (strncmp(vec[XS_WATCH_TOKEN], "hd", 2) ||
	strlen(vec[XS_WATCH_TOKEN]) != 3)
	goto out;
    hd_index = vec[XS_WATCH_TOKEN][2] - 'a';
    image = xs_read(xsh, XBT_NULL, vec[XS_WATCH_PATH], &len);
    if (image == NULL || !strcmp(image, bs_table[hd_index]->filename))
	goto out;		/* gone or identical */

    do_eject(0, vec[XS_WATCH_TOKEN]);
    bs_table[hd_index]->filename[0] = 0;
    if (hd_filename[hd_index]) {
	free(hd_filename[hd_index]);
	hd_filename[hd_index] = NULL;
    }

    if (image[0]) {
	hd_filename[hd_index] = strdup(image);
	xenstore_check_new_media_present(5000);
    }

 out:
    free(image);
    free(vec);
}

void xenstore_write_vncport(int display)
{
    char *buf = NULL, *path;
    char *portstr = NULL;

    if (xsh == NULL)
	return;

    path = xs_get_domain_path(xsh, domid);
    if (path == NULL) {
        fprintf(logfile, "xs_get_domain_path() error\n");
        goto out;
    }

    if (pasprintf(&buf, "%s/console/vnc-port", path) == -1)
	goto out;

    if (pasprintf(&portstr, "%d", 5900 + display) == -1)
	goto out;

    if (xs_write(xsh, XBT_NULL, buf, portstr, strlen(portstr)) == 0)
        fprintf(logfile, "xs_write() vncport failed\n");

 out:
    free(portstr);
    free(buf);
}

int xenstore_read_vncpasswd(int domid)
{
    extern char vncpasswd[64];
    char *buf = NULL, *path, *uuid = NULL, *passwd = NULL;
    unsigned int i, len, rc = 0;

    if (xsh == NULL) {
	return -1;
    }

    path = xs_get_domain_path(xsh, domid);
    if (path == NULL) {
	fprintf(logfile, "xs_get_domain_path() error. domid %d.\n", domid);
	return -1;
    }

    pasprintf(&buf, "%s/vm", path);
    uuid = xs_read(xsh, XBT_NULL, buf, &len);
    if (uuid == NULL) {
	fprintf(logfile, "xs_read(): uuid get error. %s.\n", buf);
	free(path);
	return -1;
    }

    pasprintf(&buf, "%s/vncpasswd", uuid);
    passwd = xs_read(xsh, XBT_NULL, buf, &len);
    if (passwd == NULL) {
	fprintf(logfile, "xs_read(): vncpasswd get error. %s.\n", buf);
	free(uuid);
	free(path);
	return rc;
    }

    for (i=0; i<len && i<63; i++) {
	vncpasswd[i] = passwd[i];
	passwd[i] = '\0';
    }
    vncpasswd[len] = '\0';
    pasprintf(&buf, "%s/vncpasswd", uuid);
    if (xs_write(xsh, XBT_NULL, buf, passwd, len) == 0) {
	fprintf(logfile, "xs_write() vncpasswd failed.\n");
	rc = -1;
    }

    free(passwd);
    free(uuid);
    free(path);

    return rc;
}
