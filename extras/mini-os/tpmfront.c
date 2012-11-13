/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * This code has been derived from drivers/char/tpm_vtpm.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (C) 2006 IBM Corporation
 *
 * This code has also been derived from drivers/char/tpm_xen.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2005, IBM Corporation
 *
 * which was itself derived from drivers/xen/netfront/netfront.c
 * from the linux kernel
 *
 * Copyright (c) 2002-2004, K A Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */
#include <mini-os/os.h>
#include <mini-os/xenbus.h>
#include <mini-os/xmalloc.h>
#include <mini-os/events.h>
#include <mini-os/wait.h>
#include <mini-os/gnttab.h>
#include <xen/io/xenbus.h>
#include <xen/io/tpmif.h>
#include <mini-os/tpmfront.h>
#include <fcntl.h>

//#define TPMFRONT_PRINT_DEBUG
#ifdef TPMFRONT_PRINT_DEBUG
#define TPMFRONT_DEBUG(fmt,...) printk("Tpmfront:Debug("__FILE__":%d) " fmt, __LINE__, ##__VA_ARGS__)
#define TPMFRONT_DEBUG_MORE(fmt,...) printk(fmt, ##__VA_ARGS__)
#else
#define TPMFRONT_DEBUG(fmt,...)
#endif
#define TPMFRONT_ERR(fmt,...) printk("Tpmfront:Error " fmt, ##__VA_ARGS__)
#define TPMFRONT_LOG(fmt,...) printk("Tpmfront:Info " fmt, ##__VA_ARGS__)

#define min(a,b) (((a) < (b)) ? (a) : (b))

void tpmfront_handler(evtchn_port_t port, struct pt_regs *regs, void *data) {
   struct tpmfront_dev* dev = (struct tpmfront_dev*) data;
   /*If we get a response when we didnt make a request, just ignore it */
   if(!dev->waiting) {
      return;
   }

   dev->waiting = 0;
#ifdef HAVE_LIBC
   if(dev->fd >= 0) {
      files[dev->fd].read = 1;
   }
#endif
   wake_up(&dev->waitq);
}

static int publish_xenbus(struct tpmfront_dev* dev) {
   xenbus_transaction_t xbt;
   int retry;
   char* err;
   /* Write the grant reference and event channel to xenstore */
again:
   if((err = xenbus_transaction_start(&xbt))) {
      TPMFRONT_ERR("Unable to start xenbus transaction, error was %s\n", err);
      free(err);
      return -1;
   }

   if((err = xenbus_printf(xbt, dev->nodename, "ring-ref", "%u", (unsigned int) dev->ring_ref))) {
      TPMFRONT_ERR("Unable to write %s/ring-ref, error was %s\n", dev->nodename, err);
      free(err);
      goto abort_transaction;
   }

   if((err = xenbus_printf(xbt, dev->nodename, "event-channel", "%u", (unsigned int) dev->evtchn))) {
      TPMFRONT_ERR("Unable to write %s/event-channel, error was %s\n", dev->nodename, err);
      free(err);
      goto abort_transaction;
   }

   if((err = xenbus_transaction_end(xbt, 0, &retry))) {
      TPMFRONT_ERR("Unable to complete xenbus transaction, error was %s\n", err);
      free(err);
      return -1;
   }
   if(retry) {
      goto again;
   }

   return 0;
abort_transaction:
   if((err = xenbus_transaction_end(xbt, 1, &retry))) {
      free(err);
   }
   return -1;
}

static int wait_for_backend_connect(xenbus_event_queue* events, char* path)
{
   int state;

   TPMFRONT_LOG("Waiting for backend connection..\n");
   /* Wait for the backend to connect */
   while(1) {
      state = xenbus_read_integer(path);
      if ( state < 0)
	 state = XenbusStateUnknown;
      switch(state) {
	 /* Bad states, we quit with error */
	 case XenbusStateUnknown:
	 case XenbusStateClosing:
	 case XenbusStateClosed:
	    TPMFRONT_ERR("Unable to connect to backend\n");
	    return -1;
	 /* If backend is connected then break out of loop */
	 case XenbusStateConnected:
	    TPMFRONT_LOG("Backend Connected\n");
	    return 0;
	 default:
	    xenbus_wait_for_watch(events);
      }
   }

}

static int wait_for_backend_closed(xenbus_event_queue* events, char* path)
{
   int state;

   TPMFRONT_LOG("Waiting for backend to close..\n");
   while(1) {
      state = xenbus_read_integer(path);
      if ( state < 0)
	 state = XenbusStateUnknown;
      switch(state) {
	 case XenbusStateUnknown:
	    TPMFRONT_ERR("Backend Unknown state, forcing shutdown\n");
	    return -1;
	 case XenbusStateClosed:
	    TPMFRONT_LOG("Backend Closed\n");
	    return 0;
	 default:
	    xenbus_wait_for_watch(events);
      }
   }

}

static int wait_for_backend_state_changed(struct tpmfront_dev* dev, XenbusState state) {
   char* err;
   int ret = 0;
   xenbus_event_queue events = NULL;
   char path[512];

   snprintf(path, 512, "%s/state", dev->bepath);
   /*Setup the watch to wait for the backend */
   if((err = xenbus_watch_path_token(XBT_NIL, path, path, &events))) {
      TPMFRONT_ERR("Could not set a watch on %s, error was %s\n", path, err);
      free(err);
      return -1;
   }

   /* Do the actual wait loop now */
   switch(state) {
      case XenbusStateConnected:
	 ret = wait_for_backend_connect(&events, path);
	 break;
      case XenbusStateClosed:
	 ret = wait_for_backend_closed(&events, path);
	 break;
      default:
	 break;
   }

   if((err = xenbus_unwatch_path_token(XBT_NIL, path, path))) {
      TPMFRONT_ERR("Unable to unwatch %s, error was %s, ignoring..\n", path, err);
      free(err);
   }
   return ret;
}

static int tpmfront_connect(struct tpmfront_dev* dev)
{
   char* err;
   /* Create shared page */
   dev->tx = (tpmif_tx_interface_t*) alloc_page();
   if(dev->tx == NULL) {
      TPMFRONT_ERR("Unable to allocate page for shared memory\n");
      goto error;
   }
   memset(dev->tx, 0, PAGE_SIZE);
   dev->ring_ref = gnttab_grant_access(dev->bedomid, virt_to_mfn(dev->tx), 0);
   TPMFRONT_DEBUG("grant ref is %lu\n", (unsigned long) dev->ring_ref);

   /*Create event channel */
   if(evtchn_alloc_unbound(dev->bedomid, tpmfront_handler, dev, &dev->evtchn)) {
      TPMFRONT_ERR("Unable to allocate event channel\n");
      goto error_postmap;
   }
   unmask_evtchn(dev->evtchn);
   TPMFRONT_DEBUG("event channel is %lu\n", (unsigned long) dev->evtchn);

   /* Write the entries to xenstore */
   if(publish_xenbus(dev)) {
      goto error_postevtchn;
   }

   /* Change state to connected */
   dev->state = XenbusStateConnected;

   /* Tell the backend that we are ready */
   if((err = xenbus_printf(XBT_NIL, dev->nodename, "state", "%u", dev->state))) {
      TPMFRONT_ERR("Unable to write to xenstore %s/state, value=%u", dev->nodename, XenbusStateConnected);
      free(err);
      goto error;
   }

   return 0;
error_postevtchn:
      mask_evtchn(dev->evtchn);
      unbind_evtchn(dev->evtchn);
error_postmap:
      gnttab_end_access(dev->ring_ref);
      free_page(dev->tx);
error:
   return -1;
}

struct tpmfront_dev* init_tpmfront(const char* _nodename)
{
   struct tpmfront_dev* dev;
   const char* nodename;
   char path[512];
   char* value, *err;
   unsigned long long ival;
   int i;

   printk("============= Init TPM Front ================\n");

   dev = malloc(sizeof(struct tpmfront_dev));
   memset(dev, 0, sizeof(struct tpmfront_dev));

#ifdef HAVE_LIBC
   dev->fd = -1;
#endif

   nodename = _nodename ? _nodename : "device/vtpm/0";
   dev->nodename = strdup(nodename);

   init_waitqueue_head(&dev->waitq);

   /* Get backend domid */
   snprintf(path, 512, "%s/backend-id", dev->nodename);
   if((err = xenbus_read(XBT_NIL, path, &value))) {
      TPMFRONT_ERR("Unable to read %s during tpmfront initialization! error = %s\n", path, err);
      free(err);
      goto error;
   }
   if(sscanf(value, "%llu", &ival) != 1) {
      TPMFRONT_ERR("%s has non-integer value (%s)\n", path, value);
      free(value);
      goto error;
   }
   free(value);
   dev->bedomid = ival;

   /* Get backend xenstore path */
   snprintf(path, 512, "%s/backend", dev->nodename);
   if((err = xenbus_read(XBT_NIL, path, &dev->bepath))) {
      TPMFRONT_ERR("Unable to read %s during tpmfront initialization! error = %s\n", path, err);
      free(err);
      goto error;
   }

   /* Create and publish grant reference and event channel */
   if (tpmfront_connect(dev)) {
      goto error;
   }

   /* Wait for backend to connect */
   if( wait_for_backend_state_changed(dev, XenbusStateConnected)) {
      goto error;
   }

   /* Allocate pages that will contain the messages */
   dev->pages = malloc(sizeof(void*) * TPMIF_TX_RING_SIZE);
   if(dev->pages == NULL) {
      goto error;
   }
   memset(dev->pages, 0, sizeof(void*) * TPMIF_TX_RING_SIZE);
   for(i = 0; i < TPMIF_TX_RING_SIZE; ++i) {
      dev->pages[i] = (void*)alloc_page();
      if(dev->pages[i] == NULL) {
	 goto error;
      }
   }

   TPMFRONT_LOG("Initialization Completed successfully\n");

   return dev;

error:
   shutdown_tpmfront(dev);
   return NULL;
}
void shutdown_tpmfront(struct tpmfront_dev* dev)
{
   char* err;
   char path[512];
   int i;
   tpmif_tx_request_t* tx;
   if(dev == NULL) {
      return;
   }
   TPMFRONT_LOG("Shutting down tpmfront\n");
   /* disconnect */
   if(dev->state == XenbusStateConnected) {
      dev->state = XenbusStateClosing;
      //FIXME: Transaction for this?
      /* Tell backend we are closing */
      if((err = xenbus_printf(XBT_NIL, dev->nodename, "state", "%u", (unsigned int) dev->state))) {
	 free(err);
      }

      /* Clean up xenstore entries */
      snprintf(path, 512, "%s/event-channel", dev->nodename);
      if((err = xenbus_rm(XBT_NIL, path))) {
	 free(err);
      }
      snprintf(path, 512, "%s/ring-ref", dev->nodename);
      if((err = xenbus_rm(XBT_NIL, path))) {
	 free(err);
      }

      /* Tell backend we are closed */
      dev->state = XenbusStateClosed;
      if((err = xenbus_printf(XBT_NIL, dev->nodename, "state", "%u", (unsigned int) dev->state))) {
	 TPMFRONT_ERR("Unable to write to %s, error was %s", dev->nodename, err);
	 free(err);
      }

      /* Wait for the backend to close and unmap shared pages, ignore any errors */
      wait_for_backend_state_changed(dev, XenbusStateClosed);

      /* Cleanup any shared pages */
      if(dev->pages) {
	 for(i = 0; i < TPMIF_TX_RING_SIZE; ++i) {
	    if(dev->pages[i]) {
	       tx = &dev->tx->ring[i].req;
	       if(tx->ref != 0) {
		  gnttab_end_access(tx->ref);
	       }
	       free_page(dev->pages[i]);
	    }
	 }
	 free(dev->pages);
      }

      /* Close event channel and unmap shared page */
      mask_evtchn(dev->evtchn);
      unbind_evtchn(dev->evtchn);
      gnttab_end_access(dev->ring_ref);

      free_page(dev->tx);

   }

   /* Cleanup memory usage */
   if(dev->respbuf) {
      free(dev->respbuf);
   }
   if(dev->bepath) {
      free(dev->bepath);
   }
   if(dev->nodename) {
      free(dev->nodename);
   }
   free(dev);
}

int tpmfront_send(struct tpmfront_dev* dev, const uint8_t* msg, size_t length)
{
   int i;
   tpmif_tx_request_t* tx = NULL;
   /* Error Checking */
   if(dev == NULL || dev->state != XenbusStateConnected) {
      TPMFRONT_ERR("Tried to send message through disconnected frontend\n");
      return -1;
   }

#ifdef TPMFRONT_PRINT_DEBUG
   TPMFRONT_DEBUG("Sending Msg to backend size=%u", (unsigned int) length);
   for(i = 0; i < length; ++i) {
      if(!(i % 30)) {
	 TPMFRONT_DEBUG_MORE("\n");
      }
      TPMFRONT_DEBUG_MORE("%02X ", msg[i]);
   }
   TPMFRONT_DEBUG_MORE("\n");
#endif

   /* Copy to shared pages now */
   for(i = 0; length > 0 && i < TPMIF_TX_RING_SIZE; ++i) {
      /* Share the page */
      tx = &dev->tx->ring[i].req;
      tx->unused = 0;
      tx->addr = virt_to_mach(dev->pages[i]);
      tx->ref = gnttab_grant_access(dev->bedomid, virt_to_mfn(dev->pages[i]), 0);
      /* Copy the bits to the page */
      tx->size = length > PAGE_SIZE ? PAGE_SIZE : length;
      memcpy(dev->pages[i], &msg[i * PAGE_SIZE], tx->size);

      /* Update counters */
      length -= tx->size;
   }
   dev->waiting = 1;
   dev->resplen = 0;
#ifdef HAVE_LIBC
   if(dev->fd >= 0) {
      files[dev->fd].read = 0;
      files[dev->fd].tpmfront.respgot = 0;
      files[dev->fd].tpmfront.offset = 0;
   }
#endif
   notify_remote_via_evtchn(dev->evtchn);
   return 0;
}
int tpmfront_recv(struct tpmfront_dev* dev, uint8_t** msg, size_t *length)
{
   tpmif_tx_request_t* tx;
   int i;
   if(dev == NULL || dev->state != XenbusStateConnected) {
      TPMFRONT_ERR("Tried to receive message from disconnected frontend\n");
      return -1;
   }
   /*Wait for the response */
   wait_event(dev->waitq, (!dev->waiting));

   /* Initialize */
   *msg = NULL;
   *length = 0;

   /* special case, just quit */
   tx = &dev->tx->ring[0].req;
   if(tx->size == 0 ) {
       goto quit;
   }
   /* Get the total size */
   tx = &dev->tx->ring[0].req;
   for(i = 0; i < TPMIF_TX_RING_SIZE && tx->size > 0; ++i) {
      tx = &dev->tx->ring[i].req;
      *length += tx->size;
   }
   /* Alloc the buffer */
   if(dev->respbuf) {
      free(dev->respbuf);
   }
   *msg = dev->respbuf = malloc(*length);
   dev->resplen = *length;
   /* Copy the bits */
   tx = &dev->tx->ring[0].req;
   for(i = 0; i < TPMIF_TX_RING_SIZE && tx->size > 0; ++i) {
      tx = &dev->tx->ring[i].req;
      memcpy(&(*msg)[i * PAGE_SIZE], dev->pages[i], tx->size);
      gnttab_end_access(tx->ref);
      tx->ref = 0;
   }
#ifdef TPMFRONT_PRINT_DEBUG
   TPMFRONT_DEBUG("Received response from backend size=%u", (unsigned int) *length);
   for(i = 0; i < *length; ++i) {
      if(!(i % 30)) {
	 TPMFRONT_DEBUG_MORE("\n");
      }
      TPMFRONT_DEBUG_MORE("%02X ", (*msg)[i]);
   }
   TPMFRONT_DEBUG_MORE("\n");
#endif
#ifdef HAVE_LIBC
   if(dev->fd >= 0) {
      files[dev->fd].tpmfront.respgot = 1;
   }
#endif
quit:
   return 0;
}

int tpmfront_cmd(struct tpmfront_dev* dev, uint8_t* req, size_t reqlen, uint8_t** resp, size_t* resplen)
{
   int rc;
   if((rc = tpmfront_send(dev, req, reqlen))) {
      return rc;
   }
   if((rc = tpmfront_recv(dev, resp, resplen))) {
      return rc;
   }

   return 0;
}

#ifdef HAVE_LIBC
#include <errno.h>
int tpmfront_open(struct tpmfront_dev* dev)
{
   /* Silently prevent multiple opens */
   if(dev->fd != -1) {
      return dev->fd;
   }

   dev->fd = alloc_fd(FTYPE_TPMFRONT);
   printk("tpmfront_open(%s) -> %d\n", dev->nodename, dev->fd);
   files[dev->fd].tpmfront.dev = dev;
   files[dev->fd].tpmfront.offset = 0;
   files[dev->fd].tpmfront.respgot = 0;
   return dev->fd;
}

int tpmfront_posix_write(int fd, const uint8_t* buf, size_t count)
{
   int rc;
   struct tpmfront_dev* dev;
   dev = files[fd].tpmfront.dev;

   if(count == 0) {
      return 0;
   }

   /* Return an error if we are already processing a command */
   if(dev->waiting) {
      errno = EINPROGRESS;
      return -1;
   }
   /* Send the command now */
   if((rc = tpmfront_send(dev, buf, count)) != 0) {
      errno = EIO;
      return -1;
   }
   return count;
}

int tpmfront_posix_read(int fd, uint8_t* buf, size_t count)
{
   int rc;
   uint8_t* dummybuf;
   size_t dummysz;
   struct tpmfront_dev* dev;

   dev = files[fd].tpmfront.dev;

   if(count == 0) {
      return 0;
   }

   /* get the response if we haven't already */
   if(files[dev->fd].tpmfront.respgot == 0) {
      if ((rc = tpmfront_recv(dev, &dummybuf, &dummysz)) != 0) {
	 errno = EIO;
	 return -1;
      }
   }

   /* handle EOF case */
   if(files[dev->fd].tpmfront.offset >= dev->resplen) {
      return 0;
   }

   /* Compute the number of bytes and do the copy operation */
   if((rc = min(count, dev->resplen - files[dev->fd].tpmfront.offset)) != 0) {
      memcpy(buf, dev->respbuf + files[dev->fd].tpmfront.offset, rc);
      files[dev->fd].tpmfront.offset += rc;
   }

   return rc;
}

int tpmfront_posix_fstat(int fd, struct stat* buf)
{
   uint8_t* dummybuf;
   size_t dummysz;
   int rc;
   struct tpmfront_dev* dev = files[fd].tpmfront.dev;

   /* If we have a response waiting, then read it now from the backend
    * so we can get its length*/
   if(dev->waiting || (files[dev->fd].read == 1 && !files[dev->fd].tpmfront.respgot)) {
      if ((rc = tpmfront_recv(dev, &dummybuf, &dummysz)) != 0) {
	 errno = EIO;
	 return -1;
      }
   }

   buf->st_mode = O_RDWR;
   buf->st_uid = 0;
   buf->st_gid = 0;
   buf->st_size = dev->resplen;
   buf->st_atime = buf->st_mtime = buf->st_ctime = time(NULL);

   return 0;
}


#endif
