/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * This code has been derived from drivers/xen/tpmback/tpmback.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2005, IBM Corporation
 *
 * which was itself derived from drivers/xen/netback/netback.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2002-2004, K A Fraser
 *
 * This code has also been derived from drivers/xen/tpmback/xenbus.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (C) 2005 IBM Corporation
 * Copyright (C) 2005 Rusty Russell <rusty@rustcorp.com.au>
 *
 * This code has also been derived from drivers/xen/tpmback/interface.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2005, IBM Corporation
 *
 * which was itself also derived from drvivers/xen/netback/interface.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2004, Keir Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License
 */
#include <mini-os/os.h>
#include <mini-os/xenbus.h>
#include <mini-os/events.h>
#include <errno.h>
#include <mini-os/gnttab.h>
#include <xen/io/xenbus.h>
#include <xen/io/tpmif.h>
#include <xen/io/protocols.h>
#include <mini-os/xmalloc.h>
#include <time.h>
#include <mini-os/tpmback.h>
#include <mini-os/lib.h>
#include <fcntl.h>
#include <mini-os/mm.h>
#include <mini-os/posix/sys/mman.h>
#include <mini-os/semaphore.h>
#include <mini-os/wait.h>


#ifndef HAVE_LIBC
#define strtoul simple_strtoul
#endif

//#define TPMBACK_PRINT_DEBUG
#ifdef TPMBACK_PRINT_DEBUG
#define TPMBACK_DEBUG(fmt,...) printk("Tpmback:Debug("__FILE__":%d) " fmt, __LINE__, ##__VA_ARGS__)
#define TPMBACK_DEBUG_MORE(fmt,...) printk(fmt, ##__VA_ARGS__)
#else
#define TPMBACK_DEBUG(fmt,...)
#endif
#define TPMBACK_ERR(fmt,...) printk("Tpmback:Error " fmt, ##__VA_ARGS__)
#define TPMBACK_LOG(fmt,...) printk("Tpmback:Info " fmt, ##__VA_ARGS__)

#define min(a,b) (((a) < (b)) ? (a) : (b))

/* Default size of the tpmif array at initialization */
#define DEF_ARRAY_SIZE 1

/* tpmif and tpmdev flags */
#define TPMIF_CLOSED 1
#define TPMIF_REQ_READY 2

struct tpmif {
   domid_t domid;
   unsigned int handle;

   char* fe_path;
   char* fe_state_path;

   /* Locally bound event channel*/
   evtchn_port_t evtchn;

   /* Shared page */
   tpmif_shared_page_t *page;

   enum xenbus_state state;
   enum { DISCONNECTED, DISCONNECTING, CONNECTED } status;

   unsigned char uuid[16];
   void* opaque;

   /* state flags */
   int flags;
};
typedef struct tpmif tpmif_t;

struct tpmback_dev {

   tpmif_t** tpmlist;
   unsigned long num_tpms;
   unsigned long num_alloc;

   struct gntmap map;

   /* True if at least one tpmif has a request to be handled */
   int flags;

   xenbus_event_queue events;

   /* Callbacks */
   void (*open_callback)(domid_t, unsigned int);
   void (*close_callback)(domid_t, unsigned int);
};
typedef struct tpmback_dev tpmback_dev_t;

enum { EV_NONE, EV_NEWFE, EV_STCHNG } tpm_ev_enum;

/* Global objects */
static struct thread* eventthread = NULL;
static tpmback_dev_t gtpmdev = {
   .tpmlist = NULL,
   .num_tpms = 0,
   .num_alloc = 0,
   .flags = TPMIF_CLOSED,
   .events = NULL,
   .open_callback = NULL,
   .close_callback = NULL,
};
struct wait_queue_head waitq;
int globalinit = 0;

/************************************
 * TPMIF SORTED ARRAY FUNCTIONS
 * tpmback_dev_t.tpmlist is a sorted array, sorted by domid and then handle number
 * Duplicates are not allowed
 * **********************************/

static void tpmif_req_ready(tpmif_t* tpmif) {
   tpmif->flags |= TPMIF_REQ_READY;
   gtpmdev.flags |= TPMIF_REQ_READY;
}

static void tpmdev_check_req(void) {
   int i;
   int flags;
   local_irq_save(flags);
   for(i = 0; i < gtpmdev.num_tpms; ++i) {
      if(gtpmdev.tpmlist[i]->flags & TPMIF_REQ_READY) {
	 gtpmdev.flags |= TPMIF_REQ_READY;
	 local_irq_restore(flags);
	 return;
      }
   }
   gtpmdev.flags &= ~TPMIF_REQ_READY;
   local_irq_restore(flags);
}

static void tpmif_req_finished(tpmif_t* tpmif) {
   tpmif->flags &= ~TPMIF_REQ_READY;
   tpmdev_check_req();
}

int __get_tpmif_index(int st, int n, domid_t domid, unsigned int handle)
{
   int i = st + n /2;
   tpmif_t* tmp;

   if( n <= 0 )
      return -1;

   tmp = gtpmdev.tpmlist[i];
   if(domid == tmp->domid && tmp->handle == handle) {
      return i;
   } else if ( (domid < tmp->domid) ||
	 (domid == tmp->domid && handle < tmp->handle)) {
      return __get_tpmif_index(st, n/2, domid, handle);
   } else {
      return __get_tpmif_index(i + 1, n/2 - ((n +1) % 2), domid, handle);
   }
}

/* Returns the array index of the tpmif domid/handle. Returns -1 if no such tpmif exists */
int get_tpmif_index(domid_t domid, unsigned int handle)
{
   int flags;
   int index;
   local_irq_save(flags);
   index = __get_tpmif_index(0, gtpmdev.num_tpms, domid, handle);
   local_irq_restore(flags);
   return index;
}

/* Returns the tpmif domid/handle or NULL if none exists */
tpmif_t* get_tpmif(domid_t domid, unsigned int handle)
{
   int flags;
   int i;
   tpmif_t* ret;
   local_irq_save(flags);
   i = get_tpmif_index(domid, handle);
   if (i < 0) {
      ret = NULL;
   } else {
      ret = gtpmdev.tpmlist[i];
   }
   local_irq_restore(flags);
   return ret;
}

/* Remove the given tpmif. Returns 0 if it was removed, -1 if it was not removed */
int remove_tpmif(tpmif_t* tpmif)
{
   int i, j;
   char* err;
   int flags;
   local_irq_save(flags);

   /* Find the index in the array if it exists */
   i = get_tpmif_index(tpmif->domid, tpmif->handle);
   if (i < 0) {
      goto error;
   }

   /* Remove the interface from the list */
   for(j = i; j < gtpmdev.num_tpms - 1; ++j) {
      gtpmdev.tpmlist[j] = gtpmdev.tpmlist[j+1];
   }
   gtpmdev.tpmlist[j] = NULL;
   --gtpmdev.num_tpms;

   /* If removed tpm was the only ready tpm, then we need to check and turn off the ready flag */
   tpmdev_check_req();

   local_irq_restore(flags);

   /* Stop listening for events on this tpm interface */
   if((err = xenbus_unwatch_path_token(XBT_NIL, tpmif->fe_state_path, tpmif->fe_state_path))) {
      TPMBACK_ERR("Unable to unwatch path token `%s' Error was %s Ignoring..\n", tpmif->fe_state_path, err);
      free(err);
   }

   return 0;
error:
   local_irq_restore(flags);
   return -1;
}

/* Insert tpmif into dev->tpmlist. Returns 0 on success and non zero on error.
 * It is an error to insert a tpmif with the same domid and handle
 * number
 * as something already in the list */
int insert_tpmif(tpmif_t* tpmif)
{
   int flags;
   unsigned int i, j;
   tpmif_t* tmp;
   char* err;
   char path[512];

   local_irq_save(flags);

   /*Check if we need to allocate more space */
   if (gtpmdev.num_tpms == gtpmdev.num_alloc) {
      gtpmdev.num_alloc *= 2;
      gtpmdev.tpmlist = realloc(gtpmdev.tpmlist, gtpmdev.num_alloc);
   }

   /*Find where to put the new interface */
   for(i = 0; i < gtpmdev.num_tpms; ++i)
   {
      tmp = gtpmdev.tpmlist[i];
      if(tpmif->domid == tmp->domid && tpmif->handle == tmp->handle) {
	 TPMBACK_ERR("Tried to insert duplicate tpm interface %u/%u\n", (unsigned int) tpmif->domid, tpmif->handle);
	 goto error;
      }
      if((tpmif->domid < tmp->domid) ||
	    (tpmif->domid == tmp->domid && tpmif->handle < tmp->handle)) {
	 break;
      }
   }

   /*Shift all the tpm pointers past i down one */
   for(j = gtpmdev.num_tpms; j > i; --j) {
      gtpmdev.tpmlist[j] = gtpmdev.tpmlist[j-1];
   }

   /*Add the new interface */
   gtpmdev.tpmlist[i] = tpmif;
   ++gtpmdev.num_tpms;

   /*Should not be needed, anything inserted with ready flag is probably an error */
   tpmdev_check_req();

   local_irq_restore(flags);

   snprintf(path, 512, "backend/vtpm/%u/%u/feature-protocol-v2", (unsigned int) tpmif->domid, tpmif->handle);
   if ((err = xenbus_write(XBT_NIL, path, "1")))
   {
      /* if we got an error here we should carefully remove the interface and then return */
      TPMBACK_ERR("Unable to write feature-protocol-v2 node: %s\n", err);
      free(err);
      remove_tpmif(tpmif);
      goto error_post_irq;
   }

   /*Listen for state changes on the new interface */
   if((err = xenbus_watch_path_token(XBT_NIL, tpmif->fe_state_path, tpmif->fe_state_path, &gtpmdev.events)))
   {
      /* if we got an error here we should carefully remove the interface and then return */
      TPMBACK_ERR("Unable to watch path token `%s' Error was %s\n", tpmif->fe_state_path, err);
      free(err);
      remove_tpmif(tpmif);
      goto error_post_irq;
   }
   return 0;
error:
   local_irq_restore(flags);
error_post_irq:
   return -1;
}


/*****************
 * CHANGE BACKEND STATE
 * *****************/
/*Attempts to change the backend state in xenstore
 * returns 0 on success and non-zero on error */
int tpmif_change_state(tpmif_t* tpmif, enum xenbus_state state)
{
   int tempst;
   char path[512];
   char *value;
   char *err;
   enum xenbus_state readst;
   TPMBACK_DEBUG("Backend state change %u/%u from=%d to=%d\n", (unsigned int) tpmif->domid, tpmif->handle, tpmif->state, state);
   if (tpmif->state == state)
      return 0;

   snprintf(path, 512, "backend/vtpm/%u/%u/state", (unsigned int) tpmif->domid, tpmif->handle);

   if((err = xenbus_read(XBT_NIL, path, &value))) {
      TPMBACK_ERR("Unable to read backend state %s, error was %s\n", path, err);
      free(err);
      return -1;
   }
   if(sscanf(value, "%d", &tempst) != 1) {
      TPMBACK_ERR("Non integer value (%s) in %s ??\n", value, path);
      free(value);
      return -1;
   }
   readst = (enum xenbus_state) tempst;
   free(value);

   /* It's possible that the backend state got updated by hotplug or something else behind our back */
   if(readst != tpmif->state) {
      TPMBACK_DEBUG("tpm interface state was %d but xenstore state was %d!\n", tpmif->state, readst);
      tpmif->state = readst;
   }

   /*If if the state isnt changing, then we dont update xenstore b/c we dont want to fire extraneous events */
   if(tpmif->state == state) {
      return 0;
   }

   /*update xenstore*/
   snprintf(path, 512, "backend/vtpm/%u/%u", (unsigned int) tpmif->domid, tpmif->handle);
   if((err = xenbus_printf(XBT_NIL, path, "state", "%u", state))) {
      TPMBACK_ERR("Error writing to xenstore %s, error was %s new state=%d\n", path, err, state);
      free(err);
      return -1;
   }

   tpmif->state = state;

   return 0;
}
/**********************************
 * TPMIF CREATION AND DELETION
 * *******************************/
static tpmif_t* __init_tpmif(domid_t domid, unsigned int handle)
{
   tpmif_t* tpmif;
   tpmif = malloc(sizeof(*tpmif));
   tpmif->domid = domid;
   tpmif->handle = handle;
   tpmif->fe_path = NULL;
   tpmif->fe_state_path = NULL;
   tpmif->state = XenbusStateInitialising;
   tpmif->status = DISCONNECTED;
   tpmif->page = NULL;
   tpmif->flags = 0;
   tpmif->opaque = NULL;
   memset(tpmif->uuid, 0, sizeof(tpmif->uuid));
   return tpmif;
}

void __free_tpmif(tpmif_t* tpmif)
{
   if(tpmif->fe_path) {
      free(tpmif->fe_path);
   }
   if(tpmif->fe_state_path) {
      free(tpmif->fe_state_path);
   }
   free(tpmif);
}
/* Creates a new tpm interface, adds it to the sorted array and returns it.
 * returns NULL on error
 * If the tpm interface already exists, it is returned*/
tpmif_t* new_tpmif(domid_t domid, unsigned int handle)
{
   tpmif_t* tpmif;
   char* err;
   char path[512];

   /* Make sure we haven't already created this tpm
    * Double events can occur */
   if((tpmif = get_tpmif(domid, handle)) != NULL) {
      return tpmif;
   }

   tpmif = __init_tpmif(domid, handle);

   /* Get the uuid from xenstore */
   snprintf(path, 512, "backend/vtpm/%u/%u/uuid", (unsigned int) domid, handle);
   if((!xenbus_read_uuid(path, tpmif->uuid))) {
      TPMBACK_ERR("Error reading %s\n", path);
      goto error;
   }

   if(tpmif_change_state(tpmif, XenbusStateInitWait)) {
      goto error;
   }

   snprintf(path, 512, "backend/vtpm/%u/%u/frontend", (unsigned int) domid, handle);
   if((err = xenbus_read(XBT_NIL, path, &tpmif->fe_path))) {
      TPMBACK_ERR("Error creating new tpm instance xenbus_read(%s), Error = %s", path, err);
      free(err);
      goto error;
   }

   /*Set the state path */
   tpmif->fe_state_path = malloc(strlen(tpmif->fe_path) + 7);
   strcpy(tpmif->fe_state_path, tpmif->fe_path);
   strcat(tpmif->fe_state_path, "/state");

   if(insert_tpmif(tpmif)) {
      goto error;
   }
   TPMBACK_DEBUG("New tpmif %u/%u\n", (unsigned int) tpmif->domid, tpmif->handle);
   /* Do the callback now */
   if(gtpmdev.open_callback) {
      gtpmdev.open_callback(tpmif->domid, tpmif->handle);
   }
   return tpmif;
error:
   __free_tpmif(tpmif);
   return NULL;

}

/* Removes tpmif from dev->tpmlist and frees it's memory usage */
void free_tpmif(tpmif_t* tpmif)
{
   char* err;
   char path[512];
   TPMBACK_DEBUG("Free tpmif %u/%u\n", (unsigned int) tpmif->domid, tpmif->handle);
   if(tpmif->flags & TPMIF_CLOSED) {
      TPMBACK_ERR("Tried to free an instance twice! Theres a bug somewhere!\n");
      BUG();
   }
   tpmif->flags = TPMIF_CLOSED;

   tpmif_change_state(tpmif, XenbusStateClosing);

   /* Unmap share page and unbind event channel */
   if(tpmif->status == CONNECTED) {
      tpmif->status = DISCONNECTING;
      mask_evtchn(tpmif->evtchn);

      if(gntmap_munmap(&gtpmdev.map, (unsigned long)tpmif->page, 1)) {
	 TPMBACK_ERR("%u/%u Error occured while trying to unmap shared page\n", (unsigned int) tpmif->domid, tpmif->handle);
      }

      unbind_evtchn(tpmif->evtchn);
   }
   tpmif->status = DISCONNECTED;
   tpmif_change_state(tpmif, XenbusStateClosed);

   /* Do the callback now */
   if(gtpmdev.close_callback) {
      gtpmdev.close_callback(tpmif->domid, tpmif->handle);
   }

   /* remove from array */
   remove_tpmif(tpmif);

   /* Wake up anyone possibly waiting on this interface and let them exit */
   wake_up(&waitq);
   schedule();

   /* Remove the old xenbus entries */
   snprintf(path, 512, "backend/vtpm/%u/%u", (unsigned int) tpmif->domid, tpmif->handle);
   if((err = xenbus_rm(XBT_NIL, path))) {
      TPMBACK_ERR("Error cleaning up xenbus entries path=%s error=%s\n", path, err);
      free(err);
   }

   TPMBACK_LOG("Frontend %u/%u disconnected\n", (unsigned int) tpmif->domid, tpmif->handle);

   /* free memory */
   __free_tpmif(tpmif);

}

/**********************
 * REMAINING TPMBACK FUNCTIONS
 * ********************/

/*Event channel handler */
void tpmback_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
   tpmif_t* tpmif = (tpmif_t*) data;
   tpmif_shared_page_t *pg = tpmif->page;

   switch (pg->state)
   {
   case TPMIF_STATE_SUBMIT:
      TPMBACK_DEBUG("EVENT CHANNEL FIRE %u/%u\n", (unsigned int) tpmif->domid, tpmif->handle);
      tpmif_req_ready(tpmif);
      wake_up(&waitq);
      break;
   case TPMIF_STATE_CANCEL:
      /* If we are busy with a request, do nothing */
      if (tpmif->flags & TPMIF_REQ_READY)
         return;
      /* Acknowledge the cancellation if we are idle */
      pg->state = TPMIF_STATE_IDLE;
      wmb();
      notify_remote_via_evtchn(tpmif->evtchn);
      return;
   default:
      /* Spurious wakeup; do nothing */
      return;
   }
}

/* Connect to frontend */
int connect_fe(tpmif_t* tpmif)
{
   char path[512];
   char* err, *value;
   uint32_t domid;
   grant_ref_t ringref;
   evtchn_port_t evtchn;

   /* If already connected then quit */
   if (tpmif->status == CONNECTED) {
      TPMBACK_DEBUG("%u/%u tried to connect while it was already connected?\n", (unsigned int) tpmif->domid, tpmif->handle);
      return 0;
   }

   /* Fetch the grant reference */
   snprintf(path, 512, "%s/ring-ref", tpmif->fe_path);
   if((err = xenbus_read(XBT_NIL, path, &value))) {
      TPMBACK_ERR("Error creating new tpm instance xenbus_read(%s) Error = %s", path, err);
      free(err);
      return -1;
   }
   if(sscanf(value, "%d", &ringref) != 1) {
      TPMBACK_ERR("Non integer value (%s) in %s ??\n", value, path);
      free(value);
      return -1;
   }
   free(value);


   /* Fetch the event channel*/
   snprintf(path, 512, "%s/event-channel", tpmif->fe_path);
   if((err = xenbus_read(XBT_NIL, path, &value))) {
      TPMBACK_ERR("Error creating new tpm instance xenbus_read(%s) Error = %s", path, err);
      free(err);
      return -1;
   }
   if(sscanf(value, "%d", &evtchn) != 1) {
      TPMBACK_ERR("Non integer value (%s) in %s ??\n", value, path);
      free(value);
      return -1;
   }
   free(value);

   /* Check that protocol v2 is being used */
   snprintf(path, 512, "%s/feature-protocol-v2", tpmif->fe_path);
   if((err = xenbus_read(XBT_NIL, path, &value))) {
      TPMBACK_ERR("Unable to read %s during tpmback initialization! error = %s\n", path, err);
      free(err);
      return -1;
   }
   if(strcmp(value, "1")) {
      TPMBACK_ERR("%s has an invalid value (%s)\n", path, value);
      free(value);
      return -1;
   }
   free(value);

   domid = tpmif->domid;
   if((tpmif->page = gntmap_map_grant_refs(&gtpmdev.map, 1, &domid, 0, &ringref, PROT_READ | PROT_WRITE)) == NULL) {
      TPMBACK_ERR("Failed to map grant reference %u/%u\n", (unsigned int) tpmif->domid, tpmif->handle);
      return -1;
   }

   /*Bind the event channel */
   if((evtchn_bind_interdomain(tpmif->domid, evtchn, tpmback_handler, tpmif, &tpmif->evtchn)))
   {
      TPMBACK_ERR("%u/%u Unable to bind to interdomain event channel!\n", (unsigned int) tpmif->domid, tpmif->handle);
      goto error_post_map;
   }
   unmask_evtchn(tpmif->evtchn);

   /* Write the ready flag and change status to connected */
   snprintf(path, 512, "backend/vtpm/%u/%u", (unsigned int) tpmif->domid, tpmif->handle);
   if((err = xenbus_printf(XBT_NIL, path, "ready", "%u", 1))) {
      TPMBACK_ERR("%u/%u Unable to write ready flag on connect_fe()\n", (unsigned int) tpmif->domid, tpmif->handle);
      free(err);
      goto error_post_evtchn;
   }
   tpmif->status = CONNECTED;
   if((tpmif_change_state(tpmif, XenbusStateConnected))){
      goto error_post_evtchn;
   }

   TPMBACK_LOG("Frontend %u/%u connected\n", (unsigned int) tpmif->domid, tpmif->handle);

   return 0;
error_post_evtchn:
   mask_evtchn(tpmif->evtchn);
   unbind_evtchn(tpmif->evtchn);
error_post_map:
   gntmap_munmap(&gtpmdev.map, (unsigned long)tpmif->page, 1);
   return -1;
}

static void disconnect_fe(tpmif_t* tpmif)
{
   if (tpmif->status == CONNECTED) {
      tpmif->status = DISCONNECTING;
      mask_evtchn(tpmif->evtchn);

      if(gntmap_munmap(&gtpmdev.map, (unsigned long)tpmif->page, 1)) {
	 TPMBACK_ERR("%u/%u Error occured while trying to unmap shared page\n", (unsigned int) tpmif->domid, tpmif->handle);
      }

      unbind_evtchn(tpmif->evtchn);
   }
   tpmif->status = DISCONNECTED;
   tpmif_change_state(tpmif, XenbusStateInitWait);

   TPMBACK_LOG("Frontend %u/%u disconnected\n", (unsigned int) tpmif->domid, tpmif->handle);
}

static int frontend_changed(tpmif_t* tpmif)
{
   int state = xenbus_read_integer(tpmif->fe_state_path);
   if(state < 0) {
      state = XenbusStateUnknown;
   }

   TPMBACK_DEBUG("Frontend %u/%u state changed to %d\n", (unsigned int) tpmif->domid, tpmif->handle, state);

   switch (state) {
      case XenbusStateInitialising:
	 break;

      case XenbusStateInitialised:
      case XenbusStateConnected:
	 if(connect_fe(tpmif)) {
	    TPMBACK_ERR("Failed to connect to front end %u/%u\n", (unsigned int) tpmif->domid, tpmif->handle);
	    tpmif_change_state(tpmif, XenbusStateClosed);
	    return -1;
	 }
	 break;

      case XenbusStateClosing:
	 tpmif_change_state(tpmif, XenbusStateClosing);
	 break;

      case XenbusStateClosed:
         disconnect_fe(tpmif);
	 break;

      case XenbusStateUnknown: /* keep it here */
	 free_tpmif(tpmif);
	 break;

      default:
	 TPMBACK_DEBUG("BAD STATE CHANGE %u/%u state = %d for tpmif\n", (unsigned int) tpmif->domid, tpmif->handle, state);
	 return -1;
   }
   return 0;
}


/* parses the string that comes out of xenbus_watch_wait_return. */
static int parse_eventstr(const char* evstr, domid_t* domid, unsigned int* handle)
{
   int ret;
   char cmd[40];
   char* err;
   char* value;
   unsigned int udomid = 0;
   tpmif_t* tpmif;
   /* First check for new frontends, this occurs when /backend/vtpm/<domid>/<handle> gets created. Note we what the sscanf to fail on the last %s */
   if (sscanf(evstr, "backend/vtpm/%u/%u/%40s", &udomid, handle, cmd) == 2) {
      *domid = udomid;
      /* Make sure the entry exists, if this event triggers because the entry dissapeared then ignore it */
      if((err = xenbus_read(XBT_NIL, evstr, &value))) {
	 free(err);
	 return EV_NONE;
      }
      free(value);
      /* Make sure the tpmif entry does not already exist, this should not happen */
      if((tpmif = get_tpmif(*domid, *handle)) != NULL) {
	 TPMBACK_DEBUG("Duplicate tpm entries! %u %u\n", tpmif->domid, tpmif->handle);
	 return EV_NONE;
      }
      return EV_NEWFE;
   } else if((ret = sscanf(evstr, "/local/domain/%u/device/vtpm/%u/%40s", &udomid, handle, cmd)) == 3) {
      *domid = udomid;
      if (!strcmp(cmd, "state"))
	 return EV_STCHNG;
   }
   return EV_NONE;
}

void handle_backend_event(char* evstr) {
   tpmif_t* tpmif;
   domid_t domid;
   unsigned int handle;
   int event;

   TPMBACK_DEBUG("Xenbus Event: %s\n", evstr);

   event = parse_eventstr(evstr, &domid, &handle);

   switch(event) {
      case EV_NEWFE:
	 if(new_tpmif(domid, handle) == NULL) {
	    TPMBACK_ERR("Failed to create new tpm instance %u/%u\n", (unsigned int) domid, handle);
	 }
	 wake_up(&waitq);
	 break;
      case EV_STCHNG:
	 if((tpmif = get_tpmif(domid, handle))) {
	    frontend_changed(tpmif);
	 } else {
	    TPMBACK_DEBUG("Event Received for non-existant tpm! instance=%u/%u xenbus_event=%s\n", (unsigned int) domid, handle, evstr);
	 }
	 break;
   }
}

/* Runs through the given path and creates events recursively
 * for all of its children.
 * @path - xenstore path to scan */
static void generate_backend_events(const char* path)
{
   char* err;
   int i, len;
   char **dirs;
   char *entry;

   if((err = xenbus_ls(XBT_NIL, path, &dirs)) != NULL) {
      free(err);
      return;
   }

   for(i = 0; dirs[i] != NULL; ++i) {
      len = strlen(path) + strlen(dirs[i]) + 2;
      entry = malloc(len);
      snprintf(entry, len, "%s/%s", path, dirs[i]);

      /* Generate and handle event for the entry itself */
      handle_backend_event(entry);

      /* Do children */
      generate_backend_events(entry);

      /* Cleanup */
      free(entry);
      free(dirs[i]);
   }
   free(dirs);
   return;
}

void* tpmback_get_opaque(domid_t domid, unsigned int handle)
{
   tpmif_t* tpmif;
   if((tpmif = get_tpmif(domid, handle)) == NULL) {
      TPMBACK_DEBUG("get_opaque() failed, %u/%u is an invalid frontend\n", (unsigned int) domid, handle);
      return NULL;
   }

   return tpmif->opaque;
}

int tpmback_set_opaque(domid_t domid, unsigned int handle, void *opaque)
{
   tpmif_t* tpmif;
   if((tpmif = get_tpmif(domid, handle)) == NULL) {
      TPMBACK_DEBUG("set_opaque() failed, %u/%u is an invalid frontend\n", (unsigned int) domid, handle);
      return -1;
   }

   tpmif->opaque = opaque;
   return 0;
}

unsigned char* tpmback_get_uuid(domid_t domid, unsigned int handle)
{
   tpmif_t* tpmif;
   if((tpmif = get_tpmif(domid, handle)) == NULL) {
      TPMBACK_DEBUG("get_uuid() failed, %u/%u is an invalid frontend\n", (unsigned int) domid, handle);
      return NULL;
   }

   return tpmif->uuid;
}

int tpmback_get_peercontext(domid_t domid, unsigned int handle, void* buffer, int buflen)
{
   tpmif_t* tpmif;
   if((tpmif = get_tpmif(domid, handle)) == NULL) {
      TPMBACK_DEBUG("get_uuid() failed, %u/%u is an invalid frontend\n", (unsigned int) domid, handle);
      return -1;
   }

   return evtchn_get_peercontext(tpmif->evtchn, buffer, buflen);
}

static void event_listener(void)
{
   const char* bepath = "backend/vtpm";
   char **path;
   char* err;

   /* Setup the backend device watch */
   if((err = xenbus_watch_path_token(XBT_NIL, bepath, bepath, &gtpmdev.events)) != NULL) {
      TPMBACK_ERR("xenbus_watch_path_token(%s) failed with error %s!\n", bepath, err);
      free(err);
      goto egress;
   }

   /* Check for any frontends that connected before we set the watch.
    * This is almost guaranteed to happen if both domains are started
    * immediatly one after the other.
    * We do this by manually generating events on everything in the backend
    * path */
   generate_backend_events(bepath);

   /* Wait and listen for changes in frontend connections */
   while(1) {
      path = xenbus_wait_for_watch_return(&gtpmdev.events);

      /*If quit flag was set then exit */
      if(gtpmdev.flags & TPMIF_CLOSED) {
	 TPMBACK_DEBUG("listener thread got quit event. Exiting..\n");
	 free(path);
	 break;
      }
      handle_backend_event(*path);
      free(path);

   }

   if((err = xenbus_unwatch_path_token(XBT_NIL, bepath, bepath)) != NULL) {
      free(err);
   }
egress:
   return;
}

void event_thread(void* p) {
   event_listener();
}

void init_tpmback(void (*open_cb)(domid_t, unsigned int), void (*close_cb)(domid_t, unsigned int))
{
   if(!globalinit) {
      init_waitqueue_head(&waitq);
      globalinit = 1;
   }
   printk("============= Init TPM BACK ================\n");
   gtpmdev.tpmlist = malloc(sizeof(tpmif_t*) * DEF_ARRAY_SIZE);
   gtpmdev.num_alloc = DEF_ARRAY_SIZE;
   gtpmdev.num_tpms = 0;
   gtpmdev.flags = 0;

   gtpmdev.open_callback = open_cb;
   gtpmdev.close_callback = close_cb;

   eventthread = create_thread("tpmback-listener", event_thread, NULL);

}

void shutdown_tpmback(void)
{
   TPMBACK_LOG("Shutting down tpm backend\n");
   /* Set the quit flag */
   gtpmdev.flags = TPMIF_CLOSED;

   //printk("num tpms is %d\n", gtpmdev.num_tpms);
   /*Free all backend instances */
   while(gtpmdev.num_tpms) {
      free_tpmif(gtpmdev.tpmlist[0]);
   }
   free(gtpmdev.tpmlist);
   gtpmdev.tpmlist = NULL;
   gtpmdev.num_alloc = 0;

   /* Wake up anyone possibly waiting on the device and let them exit */
   wake_up(&waitq);
   schedule();
}

static void init_tpmcmd(tpmcmd_t* tpmcmd, domid_t domid, unsigned int handle, void *opaque)
{
   tpmcmd->domid = domid;
   tpmcmd->locality = -1;
   tpmcmd->handle = handle;
   tpmcmd->opaque = opaque;
   tpmcmd->req = NULL;
   tpmcmd->req_len = 0;
   tpmcmd->resp = NULL;
   tpmcmd->resp_len = 0;
}

tpmcmd_t* get_request(tpmif_t* tpmif) {
   tpmcmd_t* cmd;
   tpmif_shared_page_t *shr;
   unsigned int offset;
   int flags;
#ifdef TPMBACK_PRINT_DEBUG
   int i;
#endif

   local_irq_save(flags);

   /* Allocate the cmd object to hold the data */
   if((cmd = malloc(sizeof(*cmd))) == NULL) {
      goto error;
   }
   init_tpmcmd(cmd, tpmif->domid, tpmif->handle, tpmif->opaque);

   shr = tpmif->page;
   cmd->req_len = shr->length;
   cmd->locality = shr->locality;
   offset = sizeof(*shr) + 4*shr->nr_extra_pages;
   if (offset > PAGE_SIZE || offset + cmd->req_len > PAGE_SIZE) {
      TPMBACK_ERR("%u/%u Command size too long for shared page!\n", (unsigned int) tpmif->domid, tpmif->handle);
      goto error;
   }
   /* Allocate the buffer */
   if(cmd->req_len) {
      if((cmd->req = malloc(cmd->req_len)) == NULL) {
	 goto error;
      }
   }
   /* Copy the bits from the shared page(s) */
   memcpy(cmd->req, offset + (uint8_t*)shr, cmd->req_len);

#ifdef TPMBACK_PRINT_DEBUG
   TPMBACK_DEBUG("Received Tpm Command from %u/%u of size %u", (unsigned int) tpmif->domid, tpmif->handle, cmd->req_len);
   for(i = 0; i < cmd->req_len; ++i) {
      if (!(i % 30)) {
	 TPMBACK_DEBUG_MORE("\n");
      }
      TPMBACK_DEBUG_MORE("%02hhX ", cmd->req[i]);
   }
   TPMBACK_DEBUG_MORE("\n\n");
#endif

   local_irq_restore(flags);
   return cmd;
error:
   if(cmd != NULL) {
      if (cmd->req != NULL) {
	 free(cmd->req);
	 cmd->req = NULL;
      }
      free(cmd);
      cmd = NULL;
   }
   local_irq_restore(flags);
   return NULL;

}

void send_response(tpmcmd_t* cmd, tpmif_t* tpmif)
{
   tpmif_shared_page_t *shr;
   unsigned int offset;
   int flags;
#ifdef TPMBACK_PRINT_DEBUG
int i;
#endif

   local_irq_save(flags);

   shr = tpmif->page;
   shr->length = cmd->resp_len;

   offset = sizeof(*shr) + 4*shr->nr_extra_pages;
   if (offset > PAGE_SIZE || offset + cmd->resp_len > PAGE_SIZE) {
      TPMBACK_ERR("%u/%u Command size too long for shared page!\n", (unsigned int) tpmif->domid, tpmif->handle);
      goto error;
   }
   memcpy(offset + (uint8_t*)shr, cmd->resp, cmd->resp_len);

#ifdef TPMBACK_PRINT_DEBUG
   TPMBACK_DEBUG("Sent response to %u/%u of size %u", (unsigned int) tpmif->domid, tpmif->handle, cmd->resp_len);
   for(i = 0; i < cmd->resp_len; ++i) {
      if (!(i % 30)) {
	 TPMBACK_DEBUG_MORE("\n");
      }
      TPMBACK_DEBUG_MORE("%02hhX ", cmd->resp[i]);
   }
   TPMBACK_DEBUG_MORE("\n\n");
#endif
   /* clear the ready flag and send the event channel notice to the frontend */
   tpmif_req_finished(tpmif);
   barrier();
   shr->state = TPMIF_STATE_FINISH;
   wmb();
   notify_remote_via_evtchn(tpmif->evtchn);
error:
   local_irq_restore(flags);
   return;
}

tpmcmd_t* tpmback_req_any(void)
{
   int i;
   /* Block until something has a request */
   wait_event(waitq, (gtpmdev.flags & (TPMIF_REQ_READY | TPMIF_CLOSED)));

   /* Check if were shutting down */
   if(gtpmdev.flags & TPMIF_CLOSED) {
      /* if something was waiting for us to give up the queue so it can shutdown, let it finish */
      schedule();
      return NULL;
   }

   for(i = 0; i < gtpmdev.num_tpms; ++i) {
      if(gtpmdev.tpmlist[i]->flags & TPMIF_REQ_READY) {
	 return get_request(gtpmdev.tpmlist[i]);
      }
   }

   TPMBACK_ERR("backend request ready flag was set but no interfaces were actually ready\n");
   return NULL;
}

tpmcmd_t* tpmback_req(domid_t domid, unsigned int handle)
{
   tpmif_t* tpmif;
   tpmif = get_tpmif(domid, handle);
   if(tpmif == NULL) {
      return NULL;
   }

   wait_event(waitq, (tpmif->flags & (TPMIF_REQ_READY | TPMIF_CLOSED) || gtpmdev.flags & TPMIF_CLOSED));

   /* Check if were shutting down */
   if(tpmif->flags & TPMIF_CLOSED || gtpmdev.flags & TPMIF_CLOSED) {
      /* if something was waiting for us to give up the queue so it can free this instance, let it finish */
      schedule();
      return NULL;
   }

   return get_request(tpmif);
}

void tpmback_resp(tpmcmd_t* tpmcmd)
{
   tpmif_t* tpmif;

   /* Get the associated interface, if it doesnt exist then just quit */
   tpmif = get_tpmif(tpmcmd->domid, tpmcmd->handle);
   if(tpmif == NULL) {
      TPMBACK_ERR("Tried to send a reponse to non existant frontend %u/%u\n", (unsigned int) tpmcmd->domid, tpmcmd->handle);
      goto end;
   }

   if(!(tpmif->flags & TPMIF_REQ_READY)) {
      TPMBACK_ERR("Tried to send response to a frontend that was not waiting for one %u/%u\n", (unsigned int) tpmcmd->domid, tpmcmd->handle);
      goto end;
   }

   /* Send response to frontend */
   send_response(tpmcmd, tpmif);

end:
   if(tpmcmd->req != NULL) {
      free(tpmcmd->req);
   }
   free(tpmcmd);
   return;
}

int tpmback_wait_for_frontend_connect(domid_t *domid, unsigned int *handle)
{
   tpmif_t* tpmif;
   int flags;
   wait_event(waitq, ((gtpmdev.num_tpms > 0) || gtpmdev.flags & TPMIF_CLOSED));
   if(gtpmdev.flags & TPMIF_CLOSED) {
      return -1;
   }
   local_irq_save(flags);
   tpmif = gtpmdev.tpmlist[0];
   *domid = tpmif->domid;
   *handle = tpmif->handle;
   local_irq_restore(flags);

   return 0;
}

int tpmback_num_frontends(void)
{
   return gtpmdev.num_tpms;
}
