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
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static struct xs_handle *xsh = NULL;
static char *media_filename[MAX_DISKS + MAX_SCSI_DISKS];
static QEMUTimer *insert_timer = NULL;

#define UWAIT_MAX (30*1000000) /* thirty seconds */
#define UWAIT     (100000)     /* 1/10th second  */

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

    for (i = 0; i < MAX_DISKS + MAX_SCSI_DISKS; i++) {
        if (media_filename[i] && bs_table[i]) {
            do_change(bs_table[i]->device_name, media_filename[i]);
            free(media_filename[i]);
            media_filename[i] = NULL;
        }
    }
}

void xenstore_check_new_media_present(int timeout)
{

    if (insert_timer == NULL)
        insert_timer = qemu_new_timer(rt_clock, insert_media, NULL);
    qemu_mod_timer(insert_timer, qemu_get_clock(rt_clock) + timeout);
}

static void waitForDevice(char *fn)
{ 
    struct stat sbuf;
    int status;
    int uwait = UWAIT_MAX;

    do {
        status = stat(fn, &sbuf);
        if (!status) break;
        usleep(UWAIT);
        uwait -= UWAIT;
    } while (uwait > 0);

    return;
}

void xenstore_parse_domain_config(int domid)
{
    char **e = NULL;
    char *buf = NULL, *path;
    char *fpath = NULL, *bpath = NULL,
        *dev = NULL, *params = NULL, *type = NULL;
    int i, is_scsi;
    unsigned int len, num, hd_index;

    for(i = 0; i < MAX_DISKS + MAX_SCSI_DISKS; i++)
        media_filename[i] = NULL;

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
        is_scsi = !strncmp(dev, "sd", 2);
        if ((strncmp(dev, "hd", 2) && !is_scsi) || strlen(dev) != 3 )
            continue;
        hd_index = dev[2] - 'a';
        if (hd_index >= (is_scsi ? MAX_SCSI_DISKS : MAX_DISKS))
            continue;
        /* read the type of the device */
        if (pasprintf(&buf, "%s/device/vbd/%s/device-type", path, e[i]) == -1)
            continue;
        free(type);
        type = xs_read(xsh, XBT_NULL, buf, &len);
        if (pasprintf(&buf, "%s/params", bpath) == -1)
            continue;
        free(params);
        params = xs_read(xsh, XBT_NULL, buf, &len);
        if (params == NULL)
            continue;
        /* 
         * check if device has a phantom vbd; the phantom is hooked
         * to the frontend device (for ease of cleanup), so lookup 
         * the frontend device, and see if there is a phantom_vbd
         * if there is, we will use resolution as the filename
         */
        if (pasprintf(&buf, "%s/device/vbd/%s/phantom_vbd", path, e[i]) == -1)
            continue;
        free(fpath);
        fpath = xs_read(xsh, XBT_NULL, buf, &len);
        if (fpath) {
            if (pasprintf(&buf, "%s/dev", fpath) == -1)
                continue;
            free(params);
            params = xs_read(xsh, XBT_NULL, buf , &len);
            if (params) {
                /* 
                 * wait for device, on timeout silently fail because we will 
                 * fail to open below
                 */
                waitForDevice(params);
            }
        }

        bs_table[hd_index + (is_scsi ? MAX_DISKS : 0)] = bdrv_new(dev);
        /* check if it is a cdrom */
        if (type && !strcmp(type, "cdrom")) {
            bdrv_set_type_hint(bs_table[hd_index], BDRV_TYPE_CDROM);
            if (pasprintf(&buf, "%s/params", bpath) != -1)
                xs_watch(xsh, buf, dev);
        }
        /* open device now if media present */
        if (params[0]) {
            if (bdrv_open(bs_table[hd_index + (is_scsi ? MAX_DISKS : 0)],
                          params, 0 /* snapshot */) < 0)
                fprintf(stderr, "qemu: could not open hard disk image '%s'\n",
                        params);
        }
    }

    /* Set a watch for log-dirty requests from the migration tools */
    if (pasprintf(&buf, "%s/logdirty/next-active", path) != -1) {
        xs_watch(xsh, buf, "logdirty");
        fprintf(logfile, "Watching %s\n", buf);
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

unsigned long *logdirty_bitmap = NULL;
unsigned long logdirty_bitmap_size;
extern int vga_ram_size, bios_size;

void xenstore_process_logdirty_event(void)
{
    char *act;
    static char *active_path = NULL;
    static char *next_active_path = NULL;
    static char *seg = NULL;
    unsigned int len;
    int i;

    fprintf(logfile, "Triggered log-dirty buffer switch\n");

    if (!seg) {
        char *path, *p, *key_ascii, key_terminated[17] = {0,};
        key_t key;
        int shmid;

        /* Find and map the shared memory segment for log-dirty bitmaps */
        if (!(path = xs_get_domain_path(xsh, domid))) {            
            fprintf(logfile, "Log-dirty: can't get domain path in store\n");
            exit(1);
        }
        if (!(path = realloc(path, strlen(path) 
                             + strlen("/logdirty/next-active") + 1))) {
            fprintf(logfile, "Log-dirty: out of memory\n");
            exit(1);
        }
        strcat(path, "/logdirty/");
        p = path + strlen(path);
        strcpy(p, "key");
        
        key_ascii = xs_read(xsh, XBT_NULL, path, &len);
        if (!key_ascii) {
            /* No key yet: wait for the next watch */
            free(path);
            return;
        }
        strncpy(key_terminated, key_ascii, 16);
        free(key_ascii);
        key = (key_t) strtoull(key_terminated, NULL, 16);

        /* Figure out how bit the log-dirty bitmaps are */
        logdirty_bitmap_size = xc_memory_op(xc_handle, 
                                            XENMEM_maximum_gpfn, &domid) + 1;
        logdirty_bitmap_size = ((logdirty_bitmap_size + HOST_LONG_BITS - 1)
                                / HOST_LONG_BITS); /* longs */
        logdirty_bitmap_size *= sizeof (unsigned long); /* bytes */

        /* Map the shared-memory segment */
        if ((shmid = shmget(key, 
                            2 * logdirty_bitmap_size, 
                            S_IRUSR|S_IWUSR)) == -1 
            || (seg = shmat(shmid, NULL, 0)) == (void *)-1) {
            fprintf(logfile, "Log-dirty: can't map segment %16.16llx (%s)\n",
                    (unsigned long long) key, strerror(errno));
            exit(1);
        }

        fprintf(logfile, "Log-dirty: mapped segment at %p\n", seg);

        /* Double-check that the bitmaps are the size we expect */
        if (logdirty_bitmap_size != *(uint32_t *)seg) {
            fprintf(logfile, "Log-dirty: got %u, calc %lu\n", 
                    *(uint32_t *)seg, logdirty_bitmap_size);
            return;
        }

        /* Remember the paths for the next-active and active entries */
        strcpy(p, "active");
        if (!(active_path = strdup(path))) {
            fprintf(logfile, "Log-dirty: out of memory\n");
            exit(1);
        }
        strcpy(p, "next-active");
        if (!(next_active_path = strdup(path))) {
            fprintf(logfile, "Log-dirty: out of memory\n");
            exit(1);
        }
        free(path);
    }
    
    /* Read the required active buffer from the store */
    act = xs_read(xsh, XBT_NULL, next_active_path, &len);
    if (!act) {
        fprintf(logfile, "Log-dirty: can't read next-active\n");
        exit(1);
    }

    /* Switch buffers */
    i = act[0] - '0';
    if (i != 0 && i != 1) {
        fprintf(logfile, "Log-dirty: bad next-active entry: %s\n", act);
        exit(1);
    }
    logdirty_bitmap = (unsigned long *)(seg + i * logdirty_bitmap_size);

    /* Ack that we've switched */
    xs_write(xsh, XBT_NULL, active_path, act, len);
    free(act);
}



void xenstore_process_event(void *opaque)
{
    char **vec, *image = NULL;
    unsigned int len, num, hd_index;

    vec = xs_read_watch(xsh, &num);
    if (!vec)
        return;

    if (!strcmp(vec[XS_WATCH_TOKEN], "logdirty")) {
        xenstore_process_logdirty_event();
        goto out;
    }

    if (strncmp(vec[XS_WATCH_TOKEN], "hd", 2) ||
        strlen(vec[XS_WATCH_TOKEN]) != 3)
        goto out;
    hd_index = vec[XS_WATCH_TOKEN][2] - 'a';
    image = xs_read(xsh, XBT_NULL, vec[XS_WATCH_PATH], &len);
    if (image == NULL || !strcmp(image, bs_table[hd_index]->filename))
        goto out;  /* gone or identical */

    do_eject(0, vec[XS_WATCH_TOKEN]);
    bs_table[hd_index]->filename[0] = 0;
    if (media_filename[hd_index]) {
        free(media_filename[hd_index]);
        media_filename[hd_index] = NULL;
    }

    if (image[0]) {
        media_filename[hd_index] = strdup(image);
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


/*
 * get all device instances of a certain type
 */
char **xenstore_domain_get_devices(struct xs_handle *handle,
                                   const char *devtype, unsigned int *num)
{
    char *path;
    char *buf = NULL;
    char **e  = NULL;

    path = xs_get_domain_path(handle, domid);
    if (path == NULL)
        goto out;

    if (pasprintf(&buf, "%s/device/%s", path,devtype) == -1)
        goto out;

    e = xs_directory(handle, XBT_NULL, buf, num);

 out:
    free(path);
    free(buf);
    return e;
}

/*
 * Check whether a domain has devices of the given type
 */
int xenstore_domain_has_devtype(struct xs_handle *handle, const char *devtype)
{
    int rc = 0;
    unsigned int num;
    char **e = xenstore_domain_get_devices(handle, devtype, &num);
    if (e)
        rc = 1;
    free(e);
    return rc;
}

/*
 * Function that creates a path to a variable of an instance of a
 * certain device
 */
static char *get_device_variable_path(const char *devtype, const char *inst,
                                      const char *var)
{
    char *buf = NULL;
    if (pasprintf(&buf, "/local/domain/0/backend/%s/%d/%s/%s",
                  devtype,
                  domid,
                  inst,
                  var) == -1) {
        free(buf);
        buf = NULL;
    }
    return buf;
}

char *xenstore_backend_read_variable(struct xs_handle *handle,
                                     const char *devtype, const char *inst,
                                     const char *var)
{
    char *value = NULL;
    char *buf = NULL;
    unsigned int len;

    buf = get_device_variable_path(devtype, inst, var);
    if (NULL == buf)
        goto out;

    value = xs_read(handle, XBT_NULL, buf, &len);

    free(buf);

 out:
    return value;
}

/*
  Read the hotplug status variable from the backend given the type
  of device and its instance.
*/
char *xenstore_read_hotplug_status(struct xs_handle *handle,
                                   const char *devtype, const char *inst)
{
    return xenstore_backend_read_variable(handle, devtype, inst,
                                          "hotplug-status");
}

/*
   Subscribe to the hotplug status of a device given the type of device and
   its instance.
   In case an error occurrs, a negative number is returned.
 */
int xenstore_subscribe_to_hotplug_status(struct xs_handle *handle,
                                         const char *devtype,
                                         const char *inst,
                                         const char *token)
{
    int rc = 0;
    char *path = get_device_variable_path(devtype, inst, "hotplug-status");

    if (path == NULL)
        return -1;

    if (0 == xs_watch(handle, path, token))
        rc = -2;

    free(path);

    return rc;
}

/*
 * Unsubscribe from a subscription to the status of a hotplug variable of
 * a device.
 */
int xenstore_unsubscribe_from_hotplug_status(struct xs_handle *handle,
                                             const char *devtype,
                                             const char *inst,
                                             const char *token)
{
    int rc = 0;
    char *path;
    path = get_device_variable_path(devtype, inst, "hotplug-status");
    if (path == NULL)
        return -1;

    if (0 == xs_unwatch(handle, path, token))
        rc = -2;

    free(path);

    return rc;
}

char *xenstore_vm_read(int domid, char *key, int *len)
{
    char *buf = NULL, *path = NULL, *value = NULL;

    if (xsh == NULL)
        goto out;

    path = xs_get_domain_path(xsh, domid);
    if (path == NULL) {
        fprintf(logfile, "xs_get_domain_path(%d): error\n", domid);
        goto out;
    }

    pasprintf(&buf, "%s/vm", path);
    free(path);
    path = xs_read(xsh, XBT_NULL, buf, NULL);
    if (path == NULL) {
        fprintf(logfile, "xs_read(%s): read error\n", buf);
        goto out;
    }

    pasprintf(&buf, "%s/%s", path, key);
    value = xs_read(xsh, XBT_NULL, buf, len);
    if (value == NULL) {
        fprintf(logfile, "xs_read(%s): read error\n", buf);
        goto out;
    }

 out:
    free(path);
    free(buf);
    return value;
}

int xenstore_vm_write(int domid, char *key, char *value)
{
    char *buf = NULL, *path = NULL;
    int rc = -1;

    if (xsh == NULL)
        goto out;

    path = xs_get_domain_path(xsh, domid);
    if (path == NULL) {
        fprintf(logfile, "xs_get_domain_path: error\n");
        goto out;
    }

    pasprintf(&buf, "%s/vm", path);
    free(path);
    path = xs_read(xsh, XBT_NULL, buf, NULL);
    if (path == NULL) {
        fprintf(logfile, "xs_read(%s): read error\n", buf);
        goto out;
    }

    pasprintf(&buf, "%s/%s", path, key);
    rc = xs_write(xsh, XBT_NULL, buf, value, strlen(value));
    if (rc) {
        fprintf(logfile, "xs_write(%s, %s): write error\n", buf, key);
        goto out;
    }

 out:
    free(path);
    free(buf);
    return rc;
}
