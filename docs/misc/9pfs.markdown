# Xen transport for 9pfs version 1 

## Background

9pfs is a network filesystem protocol developed for Plan 9. 9pfs is very
simple and describes a series of commands and responses. It is
completely independent from the communication channels, in fact many
clients and servers support multiple channels, usually called
"transports". For example the Linux client supports tcp and unix
sockets, fds, virtio and rdma.


### 9pfs protocol

This document won't cover the full 9pfs specification. Please refer to
this [paper] and this [website] for a detailed description of it.
However it is useful to know that each 9pfs request and response has the
following header:

    struct header {
    	uint32_t size;
    	uint8_t id;
    	uint16_t tag;
    } __attribute__((packed));

    0         4  5    7
    +---------+--+----+
    |  size   |id|tag |
    +---------+--+----+

- *size*
The size of the request or response.

- *id*
The 9pfs request or response operation.

- *tag*
Unique id that identifies a specific request/response pair. It is used
to multiplex operations on a single channel.

It is possible to have multiple requests in-flight at any given time.


## Rationale

This document describes a Xen based transport for 9pfs, in the
traditional PV frontend and backend format. The PV frontend is used by
the client to send commands to the server. The PV backend is used by the
9pfs server to receive commands from clients and send back responses.

The transport protocol supports multiple rings up to the maximum
supported by the backend. The size of every ring is also configurable
and can span multiple pages, up to the maximum supported by the backend
(although it cannot be more than 2MB). The design is to exploit
parallelism at the vCPU level and support multiple outstanding requests
simultaneously.

This document does not cover the 9pfs client/server design or
implementation, only the transport for it.


## Xenstore

The frontend and the backend connect via xenstore to exchange
information. The toolstack creates front and back nodes with state
[XenbusStateInitialising]. The protocol node name is **9pfs**.

Multiple rings are supported for each frontend and backend connection.

### Backend XenBus Nodes

Backend specific properties, written by the backend, read by the
frontend:

    versions
         Values:         <string>
    
         List of comma separated protocol versions supported by the backend.
         For example "1,2,3". Currently the value is just "1", as there is
         only one version. N.B.: this is the version of the Xen trasport
         protocol, not the version of 9pfs supported by the server.

    max-rings
         Values:         <uint32_t>
    
         The maximum supported number of rings per frontend.
    
    max-ring-page-order
         Values:         <uint32_t>
    
         The maximum supported size of a memory allocation in units of
         log2n(machine pages), e.g. 1 = 2 pages, 2 == 4 pages, etc. It
         must be at least 1.

Backend configuration nodes, written by the toolstack, read by the
backend:

    path
         Values:         <string>
    
         Host filesystem path to share.
    
    tag
         Values:         <string>
    
         Alphanumeric tag that identifies the 9pfs share. The client needs
         to know the tag to be able to mount it.
    
    security-model
         Values:         "none"
    
         *none*: files are stored using the same credentials as they are
                 created on the guest (no user ownership squash or remap)
         Only "none" is supported in this version of the protocol.

### Frontend XenBus Nodes

    version
         Values:         <string>
    
         Protocol version, chosen among the ones supported by the backend
         (see **versions** under [Backend XenBus Nodes]). Currently the
         value must be "1".

    num-rings
         Values:         <uint32_t>
    
         Number of rings. It needs to be lower or equal to max-rings.
    
    event-channel-<num> (event-channel-0, event-channel-1, etc)
         Values:         <uint32_t>
    
         The identifier of the Xen event channel used to signal activity
         in the ring buffer. One for each ring.
    
    ring-ref<num> (ring-ref0, ring-ref1, etc)
         Values:         <uint32_t>
    
         The Xen grant reference granting permission for the backend to
         map a page with information to setup a share ring. One for each
         ring.

### State Machine

Initialization:

    *Front*                               *Back*
    XenbusStateInitialising               XenbusStateInitialising
    - Query virtual device                - Query backend device
      properties.                           identification data.
    - Setup OS device instance.           - Publish backend features
    - Allocate and initialize the           and transport parameters
      request ring.                                      |
    - Publish transport parameters                       |
      that will be in effect during                      V
      this connection.                            XenbusStateInitWait
                 |
                 |
                 V
       XenbusStateInitialised

                                          - Query frontend transport parameters.
                                          - Connect to the request ring and
                                            event channel.
                                                         |
                                                         |
                                                         V
                                                 XenbusStateConnected

     - Query backend device properties.
     - Finalize OS virtual device
       instance.
                 |
                 |
                 V
        XenbusStateConnected

Once frontend and backend are connected, they have a shared page per
ring, which are used to setup the rings, and an event channel per ring,
which are used to send notifications.

Shutdown:

    *Front*                            *Back*
    XenbusStateConnected               XenbusStateConnected
                |
                |
                V
       XenbusStateClosing

                                       - Unmap grants
                                       - Unbind evtchns
                                                 |
                                                 |
                                                 V
                                         XenbusStateClosing

    - Unbind evtchns
    - Free rings
    - Free data structures
               |
               |
               V
       XenbusStateClosed

                                       - Free remaining data structures
                                                 |
                                                 |
                                                 V
                                         XenbusStateClosed


## Ring Setup

The shared page has the following layout:

    typedef uint32_t XEN_9PFS_RING_IDX;

    struct xen_9pfs_intf {
    	XEN_9PFS_RING_IDX in_cons, in_prod;
    	uint8_t pad[56];
    	XEN_9PFS_RING_IDX out_cons, out_prod;
    	uint8_t pad[56];

    	uint32_t ring_order;
        /* this is an array of (1 << ring_order) elements */
    	grant_ref_t ref[1];
    };

    /* not actually C compliant (ring_order changes from ring to ring) */
    struct ring_data {
        char in[((1 << ring_order) << PAGE_SHIFT) / 2];
        char out[((1 << ring_order) << PAGE_SHIFT) / 2];
    };

- **ring_order**
  It represents the order of the data ring. The following list of grant
  references is of `(1 << ring_order)` elements. It cannot be greater than
  **max-ring-page-order**, as specified by the backend on XenBus.
- **ref[]**
  The list of grant references which will contain the actual data. They are
  mapped contiguosly in virtual memory. The first half of the pages is the
  **in** array, the second half is the **out** array. The array must
  have a power of two number of elements.
- **out** is an array used as circular buffer
  It contains client requests. The producer is the frontend, the
  consumer is the backend.
- **in** is an array used as circular buffer
  It contains server responses. The producer is the backend, the
  consumer is the frontend.
- **out_cons**, **out_prod**
  Consumer and producer indices for client requests. They keep track of
  how much data has been written by the frontend to **out** and how much
  data has already been consumed by the backend. **out_prod** is
  increased by the frontend, after writing data to **out**. **out_cons**
  is increased by the backend, after reading data from **out**.
- **in_cons** and **in_prod**
  Consumer and producer indices for responses. They keep track of how
  much data has already been consumed by the frontend from the **in**
  array. **in_prod** is increased by the backend, after writing data to
  **in**.  **in_cons** is increased by the frontend, after reading data
  from **in**.

The binary layout of `struct xen_9pfs_intf` follows:

    0         4         8           64        68        72        76 
    +---------+---------+-----//-----+---------+---------+---------+
    | in_cons | in_prod |  padding   |out_cons |out_prod |ring_orde|
    +---------+---------+-----//-----+---------+---------+---------+

    76        80        84      4092      4096
    +---------+---------+----//---+---------+
    |  ref[0] |  ref[1] |         |  ref[N] |
    +---------+---------+----//---+---------+

**N.B** For one page, N is maximum 991 (4096-132)/4, but given that N
needs to be a power of two, actually max N is 512. As 512 == (1 << 9),
the maximum possible max-ring-page-order value is 9.

The binary layout of the ring buffers follow:

    0         ((1<<ring_order)<<PAGE_SHIFT)/2       ((1<<ring_order)<<PAGE_SHIFT)
    +------------//-------------+------------//-------------+
    |            in             |           out             |
    +------------//-------------+------------//-------------+

## Why ring.h is not needed

Many Xen PV protocols use the macros provided by [ring.h] to manage
their shared ring for communication. This procotol does not, because it
actually comes with two rings: the **in** ring and the **out** ring.
Each of them is mono-directional, and there is no static request size:
the producer writes opaque data to the ring. On the other end, in
[ring.h] they are combined, and the request size is static and
well-known. In this protocol:

  in -> backend to frontend only
  out-> frontend to backend only

In the case of the **in** ring, the frontend is the consumer, and the
backend is the producer. Everything is the same but mirrored for the
**out** ring.

The producer, the backend in this case, never reads from the **in**
ring. In fact, the producer doesn't need any notifications unless the
ring is full. This version of the protocol doesn't take advantage of it,
leaving room for optimizations.

On the other end, the consumer always requires notifications, unless it
is already actively reading from the ring. The producer can figure it
out, without any additional fields in the protocol, by comparing the
indexes at the beginning and the end of the function. This is similar to
what [ring.h] does.

## Ring Usage

The **in** and **out** arrays are used as circular buffers:
    
    0                               sizeof(array) == ((1<<ring_order)<<PAGE_SHIFT)/2
    +-----------------------------------+
    |to consume|    free    |to consume |
    +-----------------------------------+
               ^            ^
               prod         cons

    0                               sizeof(array)
    +-----------------------------------+
    |  free    | to consume |   free    |
    +-----------------------------------+
               ^            ^
               cons         prod

The following functions are provided to read and write to an array:

    #define MASK_XEN_9PFS_IDX(idx) ((idx) & (XEN_9PFS_RING_SIZE - 1))

    static inline void xen_9pfs_read(char *buf,
    		XEN_9PFS_RING_IDX *masked_prod, XEN_9PFS_RING_IDX *masked_cons,
    		uint8_t *h, size_t len) {
    	if (*masked_cons < *masked_prod) {
    		memcpy(h, buf + *masked_cons, len);
    	} else {
    		if (len > XEN_9PFS_RING_SIZE - *masked_cons) {
    			memcpy(h, buf + *masked_cons, XEN_9PFS_RING_SIZE - *masked_cons);
    			memcpy((char *)h + XEN_9PFS_RING_SIZE - *masked_cons, buf, len - (XEN_9PFS_RING_SIZE - *masked_cons));
    		} else {
    			memcpy(h, buf + *masked_cons, len);
    		}
    	}
    	*masked_cons = _MASK_XEN_9PFS_IDX(*masked_cons + len);
    }
    
    static inline void xen_9pfs_write(char *buf,
    		XEN_9PFS_RING_IDX *masked_prod, XEN_9PFS_RING_IDX *masked_cons,
    		uint8_t *opaque, size_t len) {
    	if (*masked_prod < *masked_cons) {
    		memcpy(buf + *masked_prod, opaque, len);
    	} else {
    		if (len > XEN_9PFS_RING_SIZE - *masked_prod) {
    			memcpy(buf + *masked_prod, opaque, XEN_9PFS_RING_SIZE - *masked_prod);
    			memcpy(buf, opaque + (XEN_9PFS_RING_SIZE - *masked_prod), len - (XEN_9PFS_RING_SIZE - *masked_prod)); 
    		} else {
    			memcpy(buf + *masked_prod, opaque, len); 
    		}
    	}
    	*masked_prod = _MASK_XEN_9PFS_IDX(*masked_prod + len);
    }

The producer (the backend for **in**, the frontend for **out**) writes to the
array in the following way:

- read *cons*, *prod* from shared memory
- general memory barrier
- verify *prod* against local copy (consumer shouldn't change it)
- write to array at position *prod* up to *cons*, wrapping around the circular
  buffer when necessary
- write memory barrier
- increase *prod*
- notify the other end via event channel

The consumer (the backend for **out**, the frontend for **in**) reads from the
array in the following way:

- read *prod*, *cons* from shared memory
- read memory barrier
- verify *cons* against local copy (producer shouldn't change it)
- read from array at position *cons* up to *prod*, wrapping around the circular
  buffer when necessary
- general memory barrier
- increase *cons*
- notify the other end via event channel

The producer takes care of writing only as many bytes as available in the buffer
up to *cons*. The consumer takes care of reading only as many bytes as available
in the buffer up to *prod*.


## Request/Response Workflow

The client chooses one of the available rings, then it sends a request
to the other end on the *out* array, following the producer workflow
described in [Ring Usage].

The server receives the notification and reads the request, following
the consumer workflow described in [Ring Usage]. The server knows how
much to read because it is specified in the *size* field of the 9pfs
header. The server processes the request and sends back a response on
the *in* array of the same ring, following the producer workflow as
usual. Thus, every request/response pair is on one ring.

The client receives a notification and reads the response from the *in*
array. The client knows how much data to read because it is specified in
the *size* field of the 9pfs header.


[paper]: https://www.usenix.org/legacy/event/usenix05/tech/freenix/full_papers/hensbergen/hensbergen.pdf
[website]: https://github.com/chaos/diod/blob/master/protocol.md
[XenbusStateInitialising]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,io,xenbus.h.html
[ring.h]: http://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=xen/include/public/io/ring.h;hb=HEAD
