/*
 * Xenstore internal state dump definitions.
 * Copyright (C) Juergen Gross, SUSE Software Solutions Germany GmbH
 *
 * Used for live-update and migration, possibly across Xenstore implementations.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XENSTORE_STATE_H
#define XENSTORE_STATE_H

#include <endian.h>
#include <sys/types.h>

#ifndef htobe32
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htobe32(x) __builtin_bswap32(x)
#else
#define htobe32(x) (x)
#endif
#endif

struct xs_state_preamble {
    char ident[8];
#define XS_STATE_IDENT    "xenstore"  /* To be used without the NUL byte. */
    uint32_t version;                 /* Version in big endian format. */
#define XS_STATE_VERSION  0x00000001
    uint32_t flags;                   /* Endianess. */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define XS_STATE_FLAGS    0x00000000  /* Little endian. */
#else
#define XS_STATE_FLAGS    0x00000001  /* Big endian. */
#endif
};

/*
 * Each record is starting with xs_state_record_header.
 * All records have a length of a multiple of 8 bytes.
 */

/* Common record layout: */
struct xs_state_record_header {
    uint32_t type;
#define XS_STATE_TYPE_END        0x00000000
#define XS_STATE_TYPE_GLOBAL     0x00000001
#define XS_STATE_TYPE_CONN       0x00000002
#define XS_STATE_TYPE_WATCH      0x00000003
#define XS_STATE_TYPE_TA         0x00000004
#define XS_STATE_TYPE_NODE       0x00000005
    uint32_t length;         /* Length of record in bytes. */
};

/* Global state of Xenstore: */
struct xs_state_global {
    int32_t socket_fd;      /* File descriptor for socket connections or -1. */
    int32_t evtchn_fd;      /* File descriptor for event channel operations. */
};

/* Connection to Xenstore: */
struct xs_state_connection {
    uint32_t conn_id;       /* Used as reference in watch and TA records. */
    uint16_t conn_type;
#define XS_STATE_CONN_TYPE_RING   0
#define XS_STATE_CONN_TYPE_SOCKET 1
    uint16_t pad;
    union {
        struct {
            uint16_t domid;  /* Domain-Id. */
            uint16_t tdomid; /* Id of target domain or DOMID_INVALID. */
            uint32_t evtchn; /* Event channel port. */
        } ring;
        int32_t socket_fd;   /* File descriptor for socket connections. */
    } spec;
    uint16_t data_in_len;    /* Number of unprocessed bytes read from conn. */
    uint16_t data_resp_len;  /* Size of partial response pending for conn. */
    uint32_t data_out_len;   /* Number of bytes not yet written to conn. */
    uint8_t  data[];         /* Pending data (read, written) + 0-7 pad bytes. */
};

/* Watch: */
struct xs_state_watch {
    uint32_t conn_id;       /* Connection this watch is associated with. */
    uint16_t path_length;   /* Number of bytes of path watched (incl. 0). */
    uint16_t token_length;  /* Number of bytes of watch token (incl. 0). */
    uint8_t data[];         /* Path bytes, token bytes, 0-7 pad bytes. */
};

/* Transaction: */
struct xs_state_transaction {
    uint32_t conn_id;       /* Connection this TA is associated with. */
    uint32_t ta_id;         /* Transaction Id. */
};

/* Node (either XS_STATE_TYPE_NODE or XS_STATE_TYPE_TANODE[_MOD]): */
struct xs_state_node_perm {
    uint8_t access;         /* Access rights. */
#define XS_STATE_NODE_PERM_NONE   'n'
#define XS_STATE_NODE_PERM_READ   'r'
#define XS_STATE_NODE_PERM_WRITE  'w'
#define XS_STATE_NODE_PERM_BOTH   'b'
    uint8_t flags;
#define XS_STATE_NODE_PERM_IGNORE 0x01 /* Stale permission, ignore for check. */
    uint16_t domid;         /* Domain-Id. */
};
struct xs_state_node {
    uint32_t conn_id;       /* Connection in case of transaction or 0. */
    uint32_t ta_id;         /* Transaction Id or 0. */
    uint16_t path_len;      /* Length of path string including NUL byte. */
    uint16_t data_len;      /* Length of node data. */
    uint16_t ta_access;
#define XS_STATE_NODE_TA_DELETED  0x0000
#define XS_STATE_NODE_TA_READ     0x0001
#define XS_STATE_NODE_TA_WRITTEN  0x0002
    uint16_t perm_n;        /* Number of permissions (0 in TA: node deleted). */
    /* Permissions (first is owner, has full access). */
    struct xs_state_node_perm perms[];
    /* Path and data follows, plus 0-7 pad bytes. */
};
#endif /* XENSTORE_STATE_H */
