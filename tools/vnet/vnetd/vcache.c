/*
 * Copyright (C) 2004 Mike Wray <mike.wray@hp.com>.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or  (at your option) any later version. This library is 
 * distributed in the  hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "allocate.h"
#include "hash_table.h"
#include "sys_net.h"
#include "sys_string.h"
#include "connection.h"
#include "marshal.h"
#include "timer.h"

#undef offsetof
#include "vnetd.h"
#include "vcache.h"

#define MODULE_NAME "VARP"
#define DEBUG 1
#undef DEBUG
#include "debug.h"

static VarpCache *vcache = NULL;

void IPMessageQueue_init(IPMessageQueue *queue, int maxlen){
    queue->msg = NULL;
    queue->len = 0;
    queue->maxlen = maxlen;
}

void IPMessageQueue_clear(IPMessageQueue *queue){
    queue->msg = NULL;
    queue->len = 0;
}

void IPMessageQueue_truncate(IPMessageQueue *queue, int n){
    IPMessage **p = &queue->msg; 
    int i;
    for(i = 1; *p; p = &(*p)->next, i++){
        if(i == n){
            *p = NULL;
            break;
        }
    }
}

void IPMessageQueue_add(IPMessageQueue *queue, IPMessage *msg){
    msg->next = queue->msg;
    queue->msg = msg;
    queue->len++;
    if(queue->len >= queue->maxlen){
        IPMessageQueue_truncate(queue, queue->maxlen);
    }
}

IPMessage * IPMessageQueue_pop(IPMessageQueue *queue){
    IPMessage *msg = NULL;
    if(queue->len > 0){
        queue->len--;
        msg = queue->msg;
        queue->msg = msg->next;
        msg->next = NULL;
    }
    return msg;
}

void VarpCache_sweep(VarpCache *z, int all);

/** Send a varp protocol message.
 *
 * @param opcode varp opcode (host order)
 * @param vnet vnet id (in network order)
 * @param vmac vmac (in network order)
 * @return 0 on success, error code otherwise
 */
int varp_send(Conn *conn, uint16_t opcode, uint32_t vnet, Vmac *vmac, uint32_t addr){
    int err = 0;
    int varp_n = sizeof(VarpHdr);
    VarpHdr varph = {};

    varph.vnetmsghdr.id     = htons(VARP_ID);
    varph.vnetmsghdr.opcode = htons(opcode);
    varph.vnet              = vnet;
    varph.vmac              = *vmac;
    varph.addr              = addr;

    if(0){
        struct sockaddr_in self;
        socklen_t self_n;
        getsockname(conn->sock, (struct sockaddr *)&self, &self_n);
        dprintf("> sockname addr=%s port=%d\n",
                inet_ntoa(self.sin_addr), ntohs(self.sin_port));
    }
    dprintf("> addr=%s opcode=%d\n",
            inet_ntoa(conn->addr.sin_addr), opcode);
    dprintf("> vnet=%d vmac=" MACFMT " addr=" IPFMT "\n",
            ntohl(vnet), MAC6TUPLE(vmac->mac), NIPQUAD(addr));
    err = marshal_bytes(conn->out, &varph, varp_n);
    marshal_flush(conn->out);
    dprintf("< err=%d\n", err);
    return err;
}

/* Test some flags.
 *
 * @param z varp entry
 * @param flags to test
 * @return nonzero if flags set
 */
int VCEntry_get_flags(VCEntry *z, int flags){
    return z->flags & flags;
}

/** Set some flags.
 *
 * @param z varp entry
 * @param flags to set
 * @param set set flags on if nonzero, off if zero
 * @return new flags value
 */
int VCEntry_set_flags(VCEntry *z, int flags, int set){
    if(set){
        z->flags |= flags;
    } else {
        z->flags &= ~flags;
    }
    return z->flags;
}

/** Print a varp entry.
 *
 * @param ventry varp entry
 */
void VCEntry_print(VCEntry *ventry){
    if(ventry){
        char *c, *d;
        switch(ventry->state){
        case VCACHE_STATE_INCOMPLETE: c = "INC"; break;
        case VCACHE_STATE_REACHABLE:  c = "RCH"; break;
        case VCACHE_STATE_FAILED:     c = "FLD"; break;
        default:                      c = "UNK"; break;
        }
        d = (VCEntry_get_flags(ventry, VCACHE_FLAG_PROBING) ? "P" : " ");

        printf("VENTRY(%p %s %s vnet=%d vmac=" MACFMT " addr=" IPFMT " time=%g)\n",
               ventry,
               c, d,
               ntohl(ventry->key.vnet),
               MAC6TUPLE(ventry->key.vmac.mac),
               NIPQUAD(ventry->addr),
               ventry->timestamp);
    } else {
        printf("VENTRY: Null!\n");
    }
}

int VCEntry_schedule(VCEntry *ventry);
void VCEntry_solicit(VCEntry *ventry);

/** Function called when a varp entry timer goes off.
 * If the entry is still incomplete, carries on probing.
 * Otherwise stops probing.
 *
 * @param arg ventry
 */
static void ventry_timer_fn(Timer *timer){
    VCEntry *ventry = timer->data;
    int probing = 0, scheduled = 0;

    //dprintf(">\n"); VCEntry_print(ventry);
    if(ventry->state == VCACHE_STATE_REACHABLE){
        // Do nothing.
    } else {
        // Probe if haven't run out of tries, otherwise fail.
        if(ventry->probes < VCACHE_PROBE_MAX){
            //probing = 1;
            ventry->probes++;
            scheduled = VCEntry_schedule(ventry);
            //VCEntry_solicit(ventry);
            probing = scheduled;
        } else {
            ventry->state = VCACHE_STATE_FAILED;
            IPMessageQueue_clear(&ventry->queue);
        }
    }
    if(!probing){
       VCEntry_set_flags(ventry,
                         (VCACHE_FLAG_PROBING
                          | VCACHE_FLAG_REMOTE_PROBE
                          | VCACHE_FLAG_LOCAL_PROBE),
                         0);
    }
    VCEntry_set_flags(ventry, VCACHE_FLAG_PROBING, probing);
    //dprintf("<\n");
}

/** Schedule the varp entry timer.
 *
 * @param ventry varp entry
 */
int VCEntry_schedule(VCEntry *ventry){
    int scheduled = 0;
    if(ventry->probes == 1){
        scheduled = 1;
        Timer_set(VCACHE_LOCAL_DELAY, ventry_timer_fn, ventry);
    } else {
        VCEntry_solicit(ventry);
    }
    return scheduled;
}   

/** Create a varp entry. Initializes the internal state.
 *
 * @param vnet vnet id
 * @param vmac virtual MAC address (copied)
 * @return ventry or null
 */
VCEntry * VCEntry_new(uint32_t vnet, Vmac *vmac){
    VCEntry *z = ALLOCATE(VCEntry);
    z->state = VCACHE_STATE_INCOMPLETE;
    z->timestamp = time_now();
    z->key.vnet = vnet;
    z->key.vmac = *vmac;
    return z;
}

/** Hash function for keys in the varp cache.
 * Hashes the vnet id and mac.
 *
 * @param k key (VCKey)
 * @return hashcode
 */
Hashcode vcache_key_hash_fn(void *k){
    VCKey *key = k;
    Hashcode h;
    h = hash_2ul(key->vnet,
                 (key->vmac.mac[0] << 24) |
                 (key->vmac.mac[1] << 16) |
                 (key->vmac.mac[2] <<  8) |
                 (key->vmac.mac[3]      ));
    h = hash_hul(h, 
                 (key->vmac.mac[4] <<   8) |
                 (key->vmac.mac[5]       ));
    return h;
}

/** Test equality for keys in the varp cache.
 * Compares vnet and mac.
 *
 * @param k1 key to compare (VCKey)
 * @param k2 key to compare (VCKey)
 * @return 1 if equal, 0 otherwise
 */
int vcache_key_equal_fn(void *k1, void *k2){
    VCKey *key1 = k1;
    VCKey *key2 = k2;
    return (key1->vnet == key2->vnet)
        && (memcmp(key1->vmac.mac, key2->vmac.mac, ETH_ALEN) == 0);
}

void VarpCache_schedule(VarpCache *z);

/** Function called when the varp table timer goes off.
 * Sweeps old varp cache entries and reschedules itself.
 *
 * @param arg varp table
 */
static void vcache_timer_fn(Timer *timer){
    VarpCache *z = timer->data;
    //dprintf("> z=%p\n", z);
    if(z){
        VarpCache_sweep(z, 0);
        VarpCache_schedule(z);
    }
    //dprintf("<\n");
}

/** Schedule the varp table timer.
 *
 * @param z varp table
 */
void VarpCache_schedule(VarpCache *z){
    Timer_set(VCACHE_ENTRY_TTL, vcache_timer_fn, z);
}

/** Print a varp table.
 *
 * @param z table
 */
void VarpCache_print(VarpCache *z){
    HashTable_for_decl(entry);
    VCEntry *ventry;

    dprintf(">\n");
    HashTable_for_each(entry, vcache->table){
        ventry = entry->value;
        VCEntry_print(ventry);
    }
    dprintf("<\n");
}

/** Print the varp cache.
 */
void vcache_print(void){
    VarpCache_print(vcache);
} 

/** Create a varp table.
 *
 * @return new table or null
 */
VarpCache * VarpCache_new(void){
    VarpCache *z = NULL;

    z = ALLOCATE(VarpCache);
    z->table = HashTable_new(VCACHE_BUCKETS);
    z->table->key_equal_fn = vcache_key_equal_fn;
    z->table->key_hash_fn = vcache_key_hash_fn;
    VarpCache_schedule(z);
    return z;
}

/** Add a new entry to the varp table.
 *
 * @param z table
 * @param vnet vnet id
 * @param vmac virtual MAC address (copied)
 * @return new entry or null
 */
VCEntry * VarpCache_add(VarpCache *z, uint32_t vnet, Vmac *vmac){
    VCEntry *ventry;
    HTEntry *entry;

    ventry = VCEntry_new(vnet, vmac);
    //dprintf("> "); VCEntry_print(ventry);
    entry = HashTable_add(z->table, ventry, ventry);
    return ventry;
}

/** Remove an entry from the varp table.
 *
 * @param z table
 * @param ventry entry to remove
 * @return removed count
 */
int VarpCache_remove(VarpCache *z, VCEntry *ventry){
    return HashTable_remove(z->table, ventry);
}

/** Lookup an entry in the varp table.
 *
 * @param z table
 * @param vnet vnet id
 * @param vmac virtual MAC addres
 * @return entry found or null
 */
VCEntry * VarpCache_lookup(VarpCache *z, uint32_t vnet, Vmac *vmac){
    VCKey key = { .vnet = vnet, .vmac = *vmac };
    VCEntry *ventry;
    ventry = HashTable_get(z->table, &key);
    return ventry;
}

void VCEntry_solicit(VCEntry *ventry){
    dprintf(">\n");
    if(VCEntry_get_flags(ventry, VCACHE_FLAG_LOCAL_PROBE)){
        dprintf("> local probe\n");
        varp_send(vnetd->bcast_conn, VARP_OP_REQUEST, ventry->key.vnet, &ventry->key.vmac, ventry->addr);
    }
    if(VCEntry_get_flags(ventry, VCACHE_FLAG_REMOTE_PROBE)){
        ConnList *l;
        dprintf("> remote probe\n");
        for(l = vnetd->connections; l; l = l->next){
            varp_send(l->conn, VARP_OP_REQUEST, ventry->key.vnet, &ventry->key.vmac, ventry->addr); 
        }
                
    }
    dprintf("<\n");
}

int VCEntry_resolve(VCEntry *ventry, IPMessage *msg, int flags){
    int err = 0;

    dprintf("> "); //VCEntry_print(ventry);
    ventry->state = VCACHE_STATE_INCOMPLETE;
    VCEntry_set_flags(ventry, flags, 1);
    IPMessageQueue_add(&ventry->queue, msg);
    if(!VCEntry_get_flags(ventry, VCACHE_FLAG_PROBING)){
        VCEntry_set_flags(ventry, VCACHE_FLAG_PROBING, 1);
        ventry->probes = 1;
        VCEntry_schedule(ventry);
        //VCEntry_solicit(ventry);
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Update a ventry. Sets the address and state to those given
 * and sets the timestamp to 'now'.
 *
 * @param ventry varp entry
 * @param addr care-of address
 * @param state state
 * @return 0 on success, error code otherwise
 */
int VCEntry_update(VCEntry *ventry, IPMessage *msg, VarpHdr *varph, int state){
    int err = 0;
    double now = time_now();

    if(VCEntry_get_flags(ventry, VCACHE_FLAG_PERMANENT)) goto exit;
    ventry->addr = varph->addr;
    ventry->timestamp = now;
    ventry->state = state;
    if(ventry->state == VCACHE_STATE_REACHABLE){
        // Process the output queue.
        IPMessage *msg;
        while((msg = IPMessageQueue_pop(&ventry->queue))){
            dprintf("> announce\n");
            varp_send(msg->conn, VARP_OP_ANNOUNCE, ventry->key.vnet, &ventry->key.vmac, ventry->addr);
        }
    }
  exit:
    return err;
}
    
/** Update the ventry corresponding to the given varp header.
 *
 * @param z table
 * @param varph varp header
 * @param state state
 * @return 0 on success, -ENOENT if no entry found
 */
int VarpCache_update(VarpCache *z, IPMessage *msg, VarpHdr *varph, int state){
    int err = 0;
    VCEntry *ventry;

    dprintf(">\n");
    ventry = VarpCache_lookup(z, varph->vnet, &varph->vmac);
    if(ventry){
        err = VCEntry_update(ventry, msg, varph, state);
    } else {
        err = -ENOENT;
    }
    dprintf("< err=%d\n", err);
    return err;
}


/** Put old varp entries into the incomplete state.
 * Permanent entries are not changed.
 * If 'all' is non-zero, all non-permanent entries
 * are put into the incomplete state, regardless of age.
 *
 * @param z table
 * @param all reset all entries if non-zero
 */
void VarpCache_sweep(VarpCache *z, int all){
    HashTable_for_decl(entry);
    VCEntry *ventry;
    double now = time_now();
    double old = now - VCACHE_ENTRY_TTL;

    dprintf(">\n");
    HashTable_for_each(entry, vcache->table){
        ventry = entry->value;
        if(!VCEntry_get_flags(ventry, VCACHE_FLAG_PERMANENT) &&
           (all || (ventry->timestamp < old))){
            ventry->state = VCACHE_STATE_INCOMPLETE;
        }
    }
    dprintf("<\n");
}

/** Forward a varp message.
 * If local forwards it to remote vnetds.
 * If not local forwards it to local net.
 *
 * @param varph varp message to forward
 * @param local whether it's local or not
 */
void vcache_forward_varp(VarpHdr *varph, int local){
    uint16_t opcode = ntohs(varph->vnetmsghdr.opcode);
    if(local){
        ConnList *l;
        for(l = vnetd->connections; l; l = l->next){
            varp_send(l->conn, opcode, varph->vnet, &varph->vmac, varph->addr); 
        }
    } else {
        varp_send(vnetd->bcast_conn, opcode, varph->vnet, &varph->vmac, varph->addr);
    }
}

/** Handle a varp request. 
 *
 * @param msg incoming message
 * @param varph varp message
 * @return 0 if ok, -ENOENT if no matching vif, or error code
 */
#if 1
int vcache_handle_request(IPMessage *msg, VarpHdr *varph, int local){
    dprintf("> local=%d\n", local);
    vcache_forward_varp(varph, local);
    dprintf("<\n");
    return 0;
}

#else
int vcache_handle_request(IPMessage *msg, VarpHdr *varph, int local){
    int err = -ENOENT;
    uint32_t vnet;
    Vmac *vmac;
    VCEntry *ventry = NULL;
    int reply = 0;

    dprintf(">\n");
    vnet = htonl(varph->vnet);
    vmac = &varph->vmac;
    ventry = VarpCache_lookup(vcache, vnet, vmac);
    if(!ventry){
        ventry = VarpCache_add(vcache, vnet, vmac);
    }
    if(local){
        // Request coming from the local subnet (on our udp port).
        if(ventry->state == VCACHE_STATE_REACHABLE){
            if(local){
                // Have an entry, and it's non-local - reply (locally).
                // Potential out-of-date cache problem.
                // Should query remotely instead of replying.
                varp_send(conn, VARP_OP_ANNOUNCE, ventry);
            }
        } else {
            // Incomplete entry. Resolve.
            VCEntry_resolve(ventry, msg, VCACHE_FLAG_REMOTE_PROBE);
        }
    } else {
        // Non-local request (on one of our tcp connetions).
        if(ventry->state == VCACHE_STATE_REACHABLE){
            if(local){
                // Have an entry and it's local - reply (remotely).
                // Potential out-of-date cache problem.
                // Should query locally instead of replying.
                varp_send(msg->conn, VARP_OP_ANNOUNCE, ventry);
            } else {
                // Have a non-local entry - do nothing and assume someone else
                // will reply.
            }
        } else {
            // Incomplete entry. Resolve.
            VCEntry_resolve(ventry, msg, VCACHE_FLAG_LOCAL_PROBE);
        }
    }
  exit:
    dprintf("< err=%d\n", err);
    return err;
}
#endif

/** Handle a varp announce message.
 * Update the matching ventry if we have one.
 *
 * @param msg incoming message
 * @param varp message
 * @return 0 if OK, -ENOENT if no matching entry
 */
int vcache_handle_announce(IPMessage *msg, VarpHdr *varph, int local){
    int err = 0;

    vcache_forward_varp(varph, local);
    err = VarpCache_update(vcache, msg, varph, VCACHE_STATE_REACHABLE);
    return err;
}

/** Handle an incoming varp message.
 *
 * @param msg incoming message
 * @return 0 if OK, error code otherwise
 */
int vcache_handle_message(IPMessage *msg, int local){
    int err = -EINVAL;
    VnetMsg *vmsg = msg->data;
    VarpHdr *varph = &vmsg->varp.varph;

    dprintf(">\n");
    if(1){
        dprintf("> src=%s:%d\n", inet_ntoa(msg->saddr.sin_addr), ntohs(msg->saddr.sin_port));
        dprintf("> dst=%s:%d\n", inet_ntoa(msg->daddr.sin_addr), ntohs(msg->daddr.sin_port));
        dprintf("> opcode=%d vnet=%u vmac=" MACFMT "\n",
                ntohs(varph->opcode), ntohl(varph->vnet), MAC6TUPLE(varph->vmac.mac));
    }
    switch(ntohs(varph->vnetmsghdr.opcode)){
    case VARP_OP_REQUEST:
        err = vcache_handle_request(msg, varph, local);
        break;
    case VARP_OP_ANNOUNCE:
        err = vcache_handle_announce(msg, varph, local);
        break;
    default:
        break;
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Initialize the varp cache.
 *
 * @return 0 on success, error code otherwise
 */
int vcache_init(void){
    int err = 0;
    
    if(!vcache){
        vcache = VarpCache_new();
    }
    return err;
}
