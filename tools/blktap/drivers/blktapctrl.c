/*
 * blktapctrl.c
 * 
 * userspace controller for the blktap disks.
 * As requests for new block devices arrive,
 * the controller spawns off a separate process
 * per-disk.
 *
 *
 * Copyright (c) 2005 Julian Chesterfield and Andrew Warfield.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/types.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <xs.h>
#include <printf.h>
#include <sys/time.h>
#include <syslog.h>
                                                                     
#include "blktaplib.h"
#include "blktapctrl.h"
#include "tapdisk.h"

#define PIDFILE "/var/run/blktapctrl.pid"

#define NUM_POLL_FDS 2
#define MSG_SIZE 4096
#define MAX_TIMEOUT 10
#define MAX_RAND_VAL 0xFFFF
#define MAX_ATTEMPTS 10

int run = 1;
int max_timeout = MAX_TIMEOUT;
int ctlfd = 0;

int blktap_major;

static int open_ctrl_socket(char *devname);
static int write_msg(int fd, int msgtype, void *ptr, void *ptr2);
static int read_msg(int fd, int msgtype, void *ptr);
static driver_list_entry_t *active_disks[MAX_DISK_TYPES];

static void init_driver_list(void)
{
	int i;

	for (i = 0; i < MAX_DISK_TYPES; i++)
		active_disks[i] = NULL;
	return;
}

static void init_rng(void)
{
	static uint32_t seed;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	seed = tv.tv_usec;
	srand48(seed);
	return;
}

static void make_blktap_dev(char *devname, int major, int minor)
{
	struct stat st;
	
	if (lstat(devname, &st) != 0) {
		/*Need to create device*/
		if (mkdir(BLKTAP_DEV_DIR, 0755) == 0)
			DPRINTF("Created %s directory\n",BLKTAP_DEV_DIR);
		if (mknod(devname, S_IFCHR|0600,
                	makedev(major, minor)) == 0)
			DPRINTF("Created %s device\n",devname);
	} else {
		DPRINTF("%s device already exists\n",devname);
		/* it already exists, but is it the same major number */
		if (((st.st_rdev>>8) & 0xff) != major) {
			DPRINTF("%s has old major %d\n",
				devname,
				(unsigned int)((st.st_rdev >> 8) & 0xff));
			/* only try again if we succed in deleting it */
			if (!unlink(devname))
				make_blktap_dev(devname, major, minor);
		}
	}
}

static int get_new_dev(int *major, int *minor, blkif_t *blkif)
{
	domid_translate_t tr;
	int ret;
	char *devname;
	
	tr.domid = blkif->domid;
        tr.busid = (unsigned short)blkif->be_id;
	ret = ioctl(ctlfd, BLKTAP_IOCTL_NEWINTF, tr );
	
	if ( (ret <= 0)||(ret > MAX_TAP_DEV) ) {
		DPRINTF("Incorrect Dev ID [%d]\n",ret);
		return -1;
	}
	
	*minor = ret;
	*major = ioctl(ctlfd, BLKTAP_IOCTL_MAJOR, ret );
	if (*major < 0) {
		DPRINTF("Incorrect Major ID [%d]\n",*major);
		return -1;
	}

	asprintf(&devname,"%s/%s%d",BLKTAP_DEV_DIR, BLKTAP_DEV_NAME, *minor);
	make_blktap_dev(devname,*major,*minor);	
	DPRINTF("Received device id %d and major %d, "
		"sent domid %d and be_id %d\n",
		*minor, *major, tr.domid, tr.busid);
	return 0;
}

static int get_tapdisk_pid(blkif_t *blkif)
{
	int ret;

	if ((ret = write_msg(blkif->fds[WRITE], CTLMSG_PID, blkif, NULL)) 
	    <= 0) {
		DPRINTF("Write_msg failed - CTLMSG_PID(%d)\n", ret);
		return -EINVAL;
	}

	if ((ret = read_msg(blkif->fds[READ], CTLMSG_PID_RSP, blkif))
	     <= 0) {
		DPRINTF("Read_msg failure - CTLMSG_PID(%d)\n", ret);
		return -EINVAL;
	}	
	return 1;
}

/* Look up the disk specified by path: 
 *   if found, dev points to the device string in the path
 *             type is the tapdisk driver type id
 *             blkif is the existing interface if this is a shared driver
 *             and NULL otherwise.
 *   return 0 on success, -1 on error.
 */

static int test_path(char *path, char **dev, int *type, blkif_t *blkif)
{
	char *ptr, handle[10];
	int i, size, found = 0;

	size = sizeof(dtypes)/sizeof(disk_info_t *);
	*type = MAX_DISK_TYPES + 1;
        blkif = NULL;

	if ( (ptr = strstr(path, ":"))!=NULL) {
		memcpy(handle, path, (ptr - path));
		*dev = ptr + 1;
		ptr = handle + (ptr - path);
		*ptr = '\0';
		DPRINTF("Detected handle: [%s]\n",handle);

		for (i = 0; i < size; i++) 
			if (strncmp(handle, dtypes[i]->handle, 
                                    (ptr - path)) ==0) {
                                found = 1;
                                break;
                        }

                if (found) {
                        *type = dtypes[i]->idnum;
                        
                        if (dtypes[i]->single_handler == 1) {
                                /* Check whether tapdisk process 
                                   already exists */
                                if (active_disks[dtypes[i]->idnum] == NULL) 
                                        blkif = NULL;
                                else 
                                        blkif = active_disks[dtypes[i]
                                                             ->idnum]->blkif;
                        }
                        return 0;
                }
        }

        /* Fall-through case, we didn't find a disk driver. */
        DPRINTF("Unknown blktap disk type [%s]!\n",handle);
        *dev = NULL;
        return -1;
}


static void add_disktype(blkif_t *blkif, int type)
{
	driver_list_entry_t *entry, **pprev;

	if (type > MAX_DISK_TYPES)
		return;

	entry = malloc(sizeof(driver_list_entry_t));
	entry->blkif = blkif;
	entry->next  = NULL;

	pprev = &active_disks[type];
	while (*pprev != NULL)
		pprev = &(*pprev)->next;

	*pprev = entry;
	entry->pprev = pprev;
}

static int del_disktype(blkif_t *blkif)
{
	driver_list_entry_t *entry, **pprev;
	int type = blkif->drivertype, count = 0, close = 0;

	if (type > MAX_DISK_TYPES)
		return 1;

	pprev = &active_disks[type];
	while ((*pprev != NULL) && ((*pprev)->blkif != blkif))
		pprev = &(*pprev)->next;

	if ((entry = *pprev) == NULL) {
		DPRINTF("DEL_DISKTYPE: No match\n");
		return 1;
	}

	*pprev = entry->next;
	if (entry->next)
		entry->next->pprev = pprev;

	DPRINTF("DEL_DISKTYPE: Freeing entry\n");
	free(entry);

	/* Caller should close() if no single controller, or list is empty. */
	return (!dtypes[type]->single_handler || (active_disks[type] == NULL));
}

static int write_msg(int fd, int msgtype, void *ptr, void *ptr2)
{
	blkif_t *blkif;
	blkif_info_t *blk;
	msg_hdr_t *msg;
	msg_newdev_t *msg_dev;
	char *p, *buf, *path;
	int msglen, len, ret;
	fd_set writefds;
	struct timeval timeout;
	image_t *image, *img;
	uint32_t seed;

	blkif = (blkif_t *)ptr;
	blk = blkif->info;
	image = blkif->prv;
	len = 0;

	switch (msgtype)
	{
	case CTLMSG_PARAMS:
		path = (char *)ptr2;
		DPRINTF("Write_msg called: CTLMSG_PARAMS, sending [%s, %s]\n",
			blk->params, path);

		msglen = sizeof(msg_hdr_t) + strlen(path) + 1;
		buf = malloc(msglen);

		/*Assign header fields*/
		msg = (msg_hdr_t *)buf;
		msg->type = CTLMSG_PARAMS;
		msg->len = msglen;
		msg->drivertype = blkif->drivertype;
		msg->readonly = blkif->readonly;

		gettimeofday(&timeout, NULL);
		msg->cookie = blkif->cookie;
		DPRINTF("Generated cookie, %d\n",blkif->cookie);

		/*Copy blk->params to msg*/
		p = buf + sizeof(msg_hdr_t);
		memcpy(p, path, strlen(path) + 1);

		break;

	case CTLMSG_NEWDEV:
		DPRINTF("Write_msg called: CTLMSG_NEWDEV\n");

		msglen = sizeof(msg_hdr_t) + sizeof(msg_newdev_t);
		buf = malloc(msglen);
		
		/*Assign header fields*/
		msg = (msg_hdr_t *)buf;
		msg->type = CTLMSG_NEWDEV;
		msg->len = msglen;
		msg->drivertype = blkif->drivertype;
		msg->cookie = blkif->cookie;
		
		msg_dev = (msg_newdev_t *)(buf + sizeof(msg_hdr_t));
		msg_dev->devnum = blkif->minor;
		msg_dev->domid = blkif->domid;

		break;

	case CTLMSG_CLOSE:
		DPRINTF("Write_msg called: CTLMSG_CLOSE\n");

		msglen = sizeof(msg_hdr_t);
		buf = malloc(msglen);
		
		/*Assign header fields*/
		msg = (msg_hdr_t *)buf;
		msg->type = CTLMSG_CLOSE;
		msg->len = msglen;
		msg->drivertype = blkif->drivertype;
		msg->cookie = blkif->cookie;
		
		break;

	case CTLMSG_PID:
		DPRINTF("Write_msg called: CTLMSG_PID\n");

		msglen = sizeof(msg_hdr_t);
		buf = malloc(msglen);
		
		/*Assign header fields*/
		msg = (msg_hdr_t *)buf;
		msg->type = CTLMSG_PID;
		msg->len = msglen;
		msg->drivertype = blkif->drivertype;
		msg->cookie = blkif->cookie;
		
		break;
		
	default:
		return -1;
	}

	/*Now send the message*/
	ret = 0;
	FD_ZERO(&writefds);
	FD_SET(fd,&writefds);
	timeout.tv_sec = max_timeout; /*Wait for up to max_timeout seconds*/
	timeout.tv_usec = 0;
	if (select(fd+1, (fd_set *) 0, &writefds, 
		  (fd_set *) 0, &timeout) > 0) {
		len = write(fd, buf, msglen);
		if (len == -1) DPRINTF("Write failed: (%d)\n",errno);
	}
	free(buf);

	return len;
}

static int read_msg(int fd, int msgtype, void *ptr)
{
	blkif_t *blkif;
	blkif_info_t *blk;
	msg_hdr_t *msg;
	msg_pid_t *msg_pid;
	char *p, *buf;
	int msglen = MSG_SIZE, len, ret;
	fd_set readfds;
	struct timeval timeout;
	image_t *image, *img;


	blkif = (blkif_t *)ptr;
	blk = blkif->info;
	image = blkif->prv;

	buf = malloc(MSG_SIZE);

	ret = 0;
	FD_ZERO(&readfds);
	FD_SET(fd,&readfds);
	timeout.tv_sec = max_timeout; /*Wait for up to max_timeout seconds*/ 
	timeout.tv_usec = 0;
	if (select(fd+1, &readfds,  (fd_set *) 0,
		  (fd_set *) 0, &timeout) > 0) {
		ret = read(fd, buf, msglen);
	}			
	if (ret > 0) {
		msg = (msg_hdr_t *)buf;
		switch (msg->type)
		{
		case CTLMSG_IMG:
			img = (image_t *)(buf + sizeof(msg_hdr_t));
			image->size = img->size;
			image->secsize = img->secsize;
			image->info = img->info;

			DPRINTF("Received CTLMSG_IMG: %llu, %lu, %u\n",
				image->size, image->secsize, image->info);
			if(msgtype != CTLMSG_IMG) ret = 0;
			break;
			
		case CTLMSG_IMG_FAIL:
			DPRINTF("Received CTLMSG_IMG_FAIL, "
				"unable to open image\n");
			ret = 0;
			break;
				
		case CTLMSG_NEWDEV_RSP:
			DPRINTF("Received CTLMSG_NEWDEV_RSP\n");
			if(msgtype != CTLMSG_NEWDEV_RSP) ret = 0;
			break;
			
		case CTLMSG_NEWDEV_FAIL:
			DPRINTF("Received CTLMSG_NEWDEV_FAIL\n");
			ret = 0;
			break;
			
		case CTLMSG_CLOSE_RSP:
			DPRINTF("Received CTLMSG_CLOSE_RSP\n");
			if (msgtype != CTLMSG_CLOSE_RSP) ret = 0;
			break;

		case CTLMSG_PID_RSP:
			DPRINTF("Received CTLMSG_PID_RSP\n");
			if (msgtype != CTLMSG_PID_RSP) ret = 0;
			else {
				msg_pid = (msg_pid_t *)
					(buf + sizeof(msg_hdr_t));
				blkif->tappid = msg_pid->pid;
				DPRINTF("\tPID: [%d]\n",blkif->tappid);
			}
			break;
		default:
			DPRINTF("UNKNOWN MESSAGE TYPE RECEIVED\n");
			ret = 0;
			break;
		}
	} 
	
	free(buf);
	
	return ret;

}

int blktapctrl_new_blkif(blkif_t *blkif)
{
	blkif_info_t *blk;
	int major, minor, fd_read, fd_write, type, new;
	char *rdctldev, *wrctldev, *cmd, *ptr;
	image_t *image;
	blkif_t *exist = NULL;

	DPRINTF("Received a poll for a new vbd\n");
	if ( ((blk=blkif->info) != NULL) && (blk->params != NULL) ) {
		if (get_new_dev(&major, &minor, blkif)<0)
			return -1;

		if (test_path(blk->params, &ptr, &type, exist) != 0) {
                        DPRINTF("Error in blktap device string(%s).\n",
                                blk->params);
                        return -1;
                }
		blkif->drivertype = type;
		blkif->cookie = lrand48() % MAX_RAND_VAL;

		if (!exist) {
			DPRINTF("Process does not exist:\n");
			asprintf(&rdctldev, "/dev/xen/tapctrlread%d", minor);
			blkif->fds[READ] = open_ctrl_socket(rdctldev);


			asprintf(&wrctldev, "/dev/xen/tapctrlwrite%d", minor);
			blkif->fds[WRITE] = open_ctrl_socket(wrctldev);
			
			if (blkif->fds[READ] == -1 || blkif->fds[WRITE] == -1) 
				goto fail;

			/*launch the new process*/
			asprintf(&cmd, "tapdisk %s %s", wrctldev, rdctldev);
			DPRINTF("Launching process, CMDLINE [%s]\n",cmd);
			if (system(cmd) == -1) {
				DPRINTF("Unable to fork, cmdline: [%s]\n",cmd);
				return -1;
			}

			free(rdctldev);
			free(wrctldev);
			free(cmd);
		} else {
			DPRINTF("Process exists!\n");
			blkif->fds[READ] = exist->fds[READ];
			blkif->fds[WRITE] = exist->fds[WRITE];
		}

		add_disktype(blkif, type);
		blkif->major = major;
		blkif->minor = minor;

		image = (image_t *)malloc(sizeof(image_t));
		blkif->prv = (void *)image;
		blkif->ops = &tapdisk_ops;

		/*Retrieve the PID of the new process*/
		if (get_tapdisk_pid(blkif) <= 0) {
			DPRINTF("Unable to contact disk process\n");
			goto fail;
		}

		/* Both of the following read and write calls will block up to 
		 * max_timeout val*/
		if (write_msg(blkif->fds[WRITE], CTLMSG_PARAMS, blkif, ptr) 
		    <= 0) {
			DPRINTF("Write_msg failed - CTLMSG_PARAMS\n");
			goto fail;
		}

		if (read_msg(blkif->fds[READ], CTLMSG_IMG, blkif) <= 0) {
			DPRINTF("Read_msg failure - CTLMSG_IMG\n");
			goto fail;
		}

	} else return -1;

	return 0;
fail:
	ioctl(ctlfd, BLKTAP_IOCTL_FREEINTF, minor);
	return -EINVAL;
}

int map_new_blktapctrl(blkif_t *blkif)
{
	DPRINTF("Received a poll for a new devmap\n");
	if (write_msg(blkif->fds[WRITE], CTLMSG_NEWDEV, blkif, NULL) <= 0) {
		DPRINTF("Write_msg failed - CTLMSG_NEWDEV\n");
		return -EINVAL;
	}

	if (read_msg(blkif->fds[READ], CTLMSG_NEWDEV_RSP, blkif) <= 0) {
		DPRINTF("Read_msg failed - CTLMSG_NEWDEV_RSP\n");
		return -EINVAL;
	}
	DPRINTF("Exiting map_new_blktapctrl\n");

	return blkif->minor - 1;
}

int unmap_blktapctrl(blkif_t *blkif)
{
	DPRINTF("Unmapping vbd\n");

	if (write_msg(blkif->fds[WRITE], CTLMSG_CLOSE, blkif, NULL) <= 0) {
		DPRINTF("Write_msg failed - CTLMSG_CLOSE\n");
		return -EINVAL;
	}

	if (del_disktype(blkif)) {
		close(blkif->fds[WRITE]);
		close(blkif->fds[READ]);
	}

	return 0;
}

int open_ctrl_socket(char *devname)
{
	int ret;
	int ipc_fd;
	char *cmd;
	fd_set socks;
	struct timeval timeout;

	ret = mkfifo(devname,S_IRWXU|S_IRWXG|S_IRWXO);
	if ( (ret != 0) && (errno != EEXIST) ) {
		DPRINTF("ERROR: pipe failed (%d)\n", errno);
		exit(0);
	}

	ipc_fd = open(devname,O_RDWR|O_NONBLOCK);

	if (ipc_fd < 0) {
		DPRINTF("FD open failed\n");
		return -1;
	}

	return ipc_fd;
}

static void print_drivers(void)
{
	int i, size;

	size = sizeof(dtypes)/sizeof(disk_info_t *);
	DPRINTF("blktapctrl: v1.0.0\n");
	for (i = 0; i < size; i++)
		DPRINTF("Found driver: [%s]\n",dtypes[i]->name);
} 

static void write_pidfile(long pid)
{
	char buf[100];
	int len;
	int fd;
	int flags;

	fd = open(PIDFILE, O_RDWR | O_CREAT, 0600);
	if (fd == -1) {
		DPRINTF("Opening pid file failed (%d)\n", errno);
		exit(1);
	}

	/* We exit silently if daemon already running. */
	if (lockf(fd, F_TLOCK, 0) == -1)
		exit(0);

	/* Set FD_CLOEXEC, so that tapdisk doesn't get this file
	   descriptor. */
	if ((flags = fcntl(fd, F_GETFD)) == -1) {
		DPRINTF("F_GETFD failed (%d)\n", errno);
		exit(1);
	}
	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1) {
		DPRINTF("F_SETFD failed (%d)\n", errno);
		exit(1);
	}

	len = sprintf(buf, "%ld\n", pid);
	if (write(fd, buf, len) != len) {
		DPRINTF("Writing pid file failed (%d)\n", errno);
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	char *devname;
	tapdev_info_t *ctlinfo;
	int tap_pfd, store_pfd, xs_fd, ret, timeout, pfd_count, count=0;
	struct xs_handle *h;
	struct pollfd  pfd[NUM_POLL_FDS];
	pid_t process;
	char buf[128];

	__init_blkif();
	snprintf(buf, sizeof(buf), "BLKTAPCTRL[%d]", getpid());
	openlog(buf, LOG_CONS|LOG_ODELAY, LOG_DAEMON);
	daemon(0,0);

	print_drivers();
	init_driver_list();
	init_rng();

	register_new_blkif_hook(blktapctrl_new_blkif);
	register_new_devmap_hook(map_new_blktapctrl);
	register_new_unmap_hook(unmap_blktapctrl);

	/* Attach to blktap0 */
	asprintf(&devname,"%s/%s0", BLKTAP_DEV_DIR, BLKTAP_DEV_NAME);
	if ((ret = xc_find_device_number("blktap0")) < 0)
		goto open_failed;
	blktap_major = major(ret);
	make_blktap_dev(devname,blktap_major,0);
	ctlfd = open(devname, O_RDWR);
	if (ctlfd == -1) {
		DPRINTF("blktap0 open failed\n");
		goto open_failed;
	}


 retry:
	/* Set up store connection and watch. */
	h = xs_daemon_open();
	if (h == NULL) {
		DPRINTF("xs_daemon_open failed -- "
			"is xenstore running?\n");
                if (count < MAX_ATTEMPTS) {
                        count++;
                        sleep(2);
                        goto retry;
                } else goto open_failed;
	}
	
	ret = setup_probe_watch(h);
	if (ret != 0) {
		DPRINTF("Failed adding device probewatch\n");
		xs_daemon_close(h);
		goto open_failed;
	}

	ioctl(ctlfd, BLKTAP_IOCTL_SETMODE, BLKTAP_MODE_INTERPOSE );

	process = getpid();
	write_pidfile(process);
	ret = ioctl(ctlfd, BLKTAP_IOCTL_SENDPID, process );

	/*Static pollhooks*/
	pfd_count = 0;
	tap_pfd = pfd_count++;
	pfd[tap_pfd].fd = ctlfd;
	pfd[tap_pfd].events = POLLIN;
	
	store_pfd = pfd_count++;
	pfd[store_pfd].fd = xs_fileno(h);
	pfd[store_pfd].events = POLLIN;

	while (run) {
		timeout = 1000; /*Milliseconds*/
                ret = poll(pfd, pfd_count, timeout);

		if (ret > 0) {
			if (pfd[store_pfd].revents) {
				ret = xs_fire_next_watch(h);
			}
		}
	}

	xs_daemon_close(h);
	ioctl(ctlfd, BLKTAP_IOCTL_SETMODE, BLKTAP_MODE_PASSTHROUGH );
	close(ctlfd);
	closelog();

	return 0;
	
 open_failed:
	DPRINTF("Unable to start blktapctrl\n");
	closelog();
	return -1;
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
