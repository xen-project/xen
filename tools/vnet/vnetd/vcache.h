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
#ifndef _VNET_VCACHE_H_
#define _VNET_VCACHE_H_

#include "hash_table.h"

/** Time-to-live of varp cache entries (in seconds).*/
#define VCACHE_ENTRY_TTL      30.0

/** Maximum number of varp probes to make. */
#define VCACHE_PROBE_MAX      5

/** Interval between varp probes (in seconds). */
#define VCACHE_PROBE_INTERVAL 3.0

/** Delay before forwarding a local probe (in seconds). */
#define VCACHE_LOCAL_DELAY    2.0

/** Number of buckets in the varp cache (must be prime). */
#define VCACHE_BUCKETS  3001

enum {
    VCACHE_STATE_INCOMPLETE = 1,
    VCACHE_STATE_REACHABLE = 2,
    VCACHE_STATE_FAILED = 3
};

enum {
    VCACHE_FLAG_PROBING = 1,
    VCACHE_FLAG_PERMANENT = 2,
    VCACHE_FLAG_LOCAL_PROBE = 4,
    VCACHE_FLAG_REMOTE_PROBE = 8,
};


#include <asm/byteorder.h>
/*
 *      Display an IP address in readable format.
 */

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD	NIPQUAD
#else
#error "Please fix asm/byteorder.h"
#endif /* __LITTLE_ENDIAN */

#define IPFMT "%u.%u.%u.%u"
#define MACFMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define MAC6TUPLE(_mac) (_mac)[0], (_mac)[1], (_mac)[2], (_mac)[3], (_mac)[4], (_mac)[5]

typedef struct IPMessage {
    Conn *conn;
    struct sockaddr_in saddr;
    struct sockaddr_in daddr;
    void *data;
    struct IPMessage *next;
} IPMessage;

typedef struct IPMessageQueue {
    IPMessage *msg;
    int len;
    int maxlen;
} IPMessageQueue;

/** Key for varp cache entries. */
typedef struct VCKey {
    /** Vnet id (network order). */
    uint32_t vnet;
    /** Virtual MAC address. */
    Vmac vmac;
} VCKey;

typedef struct VCEntry {
    /** Key for the entry. */
    VCKey key;

    /** Care-of address for the key. */
    uint32_t addr;

    /** Alias coa if we are a gateway. */
    //uint32_t gateway;
    /** Encapsulation to use (if a gateway). */
    //uint32_t encaps;

    /** Where this entry came from. */
    uint32_t source;

    /** Last-updated timestamp. */
    double timestamp;

    /** State. */
    short state;

    /** Flags. */
    short flags;

    /** Number of probes sent. */
    int probes;

    /** List of messages to reply to when completes. */
    IPMessageQueue queue;

} VCEntry;

/** The varp cache. Varp cache entries indexed by VCKey. */
typedef struct VarpCache {
    HashTable *table;
} VarpCache;

int vcache_init(void);
int vcache_handle_message(IPMessage *msg, int local);

#endif /* ! _VNET_VCACHE_H_ */
