/*
 * Shared producer-consumer ring macros.
 * Tim Deegan and Andrew Warfield November 2004.
 */ 

#ifndef __XEN_PUBLIC_IO_RING_H__
#define __XEN_PUBLIC_IO_RING_H__

typedef unsigned int RING_IDX;

/* This is horrible: it rounds a 32-bit unsigned constant down to the
 * nearest power of two, by finding the highest set bit. */
#define __RD2PO2(_x) (((_x) & 0x80000000) ? 0x80000000 :                \
                      ((_x) & 0x40000000) ? 0x40000000 :                \
                      ((_x) & 0x20000000) ? 0x20000000 :                \
                      ((_x) & 0x10000000) ? 0x10000000 :                \
                      ((_x) & 0x08000000) ? 0x08000000 :                \
                      ((_x) & 0x04000000) ? 0x04000000 :                \
                      ((_x) & 0x02000000) ? 0x02000000 :                \
                      ((_x) & 0x01000000) ? 0x01000000 :                \
                      ((_x) & 0x00800000) ? 0x00800000 :                \
                      ((_x) & 0x00400000) ? 0x00400000 :                \
                      ((_x) & 0x00200000) ? 0x00200000 :                \
                      ((_x) & 0x00100000) ? 0x00100000 :                \
                      ((_x) & 0x00080000) ? 0x00080000 :                \
                      ((_x) & 0x00040000) ? 0x00040000 :                \
                      ((_x) & 0x00020000) ? 0x00020000 :                \
                      ((_x) & 0x00010000) ? 0x00010000 :                \
                      ((_x) & 0x00008000) ? 0x00008000 :                \
                      ((_x) & 0x00004000) ? 0x00004000 :                \
                      ((_x) & 0x00002000) ? 0x00002000 :                \
                      ((_x) & 0x00001000) ? 0x00001000 :                \
                      ((_x) & 0x00000800) ? 0x00000800 :                \
                      ((_x) & 0x00000400) ? 0x00000400 :                \
                      ((_x) & 0x00000200) ? 0x00000200 :                \
                      ((_x) & 0x00000100) ? 0x00000100 :                \
                      ((_x) & 0x00000080) ? 0x00000080 :                \
                      ((_x) & 0x00000040) ? 0x00000040 :                \
                      ((_x) & 0x00000020) ? 0x00000020 :                \
                      ((_x) & 0x00000010) ? 0x00000010 :                \
                      ((_x) & 0x00000008) ? 0x00000008 :                \
                      ((_x) & 0x00000004) ? 0x00000004 :                \
                      ((_x) & 0x00000002) ? 0x00000002 :                \
                      ((_x) & 0x00000001) ? 0x00000001 : 0x00000000)

/* Given a shared ring, tell me how many entries there are in it.  The
 * rule is: a ring contains as many entries as will fit, rounded down to
 * the nearest power of two (so we can mask with (size-1) to loop
 * around) */
#define __SRING_SIZE(__params, __esize)                                 \
    __RD2PO2((sizeof((__params)->size) - (2 * sizeof(RING_IDX))) / (__esize))
#define SRING_SIZE(__params, __sringp)                                  \
    __SRING_SIZE(__params, sizeof (__sringp)->ring[0])

/*
 *  Macros to make the correct C datatypes for a new kind of ring.
 * 
 *  To make a new ring datatype, you need to have two message structures,
 *  let's say request_t, and response_t already defined.  You also need to
 *  know how big the shared memory region you want the ring to occupy is
 *  (PAGE_SIZE, of instance).
 *
 *  In a header where you want the ring datatype declared, you then do:
 *
 *   #define MY_RING RING_PARAMS(request_t, response_t, PAGE_SIZE)
 *   DEFINE_RING_TYPES(mytag, MY_RING);
 *
 *  These expand out to give you a set of types, as you can see below.
 *  The most important of these are:
 *  
 *     mytag_sring_t      - The shared ring.
 *     mytag_front_ring_t - The 'front' half of the ring.
 *     mytag_back_ring_t  - The 'back' half of the ring.
 *
 *  Use the RING_PARAMS define (MY_RING above) as a first parameter on all
 *  the ring functions.  To initialize a ring in your code, on the front 
 *  half, you do a:
 *
 *      mytag_front_ring_t front_ring;
 *
 *      SHARED_RING_INIT(MY_RING, (mytag_sring_t *)shared_page)
 *      FRONT_RING_INIT(MY_RING, &front_ring, (mytag_sring_t *)shared_page)
 *
 *  Initializing the back follows similarly...
 */
         
/*  NB: RING SIZING. (a note to ease future debugging...)
 *
 *  Passing size information into the ring macros is made difficult by 
 *  the lack of a reasonable constant declaration in C.  To get around this,
 *  the RING_PARAMS define places the requested size of the ring as the 
 *  static size of the 'size' array in the anonymous RING_PARAMS struct.
 *  While this struct is never actually instantiated, __SRING_SIZE is 
 *  able to use sizeof() to get at the constant size.
 */

#define RING_PARAMS(__req_t, __rsp_t, __size)                           \
((struct {                                                              \
    char size[__size];                                                  \
    __req_t req;                                                        \
    __rsp_t rsp;                                                        \
                                                                        \
} *) 0)


#define DEFINE_RING_TYPES(__name, __params)                             \
                                                                        \
/* Shared ring entry */                                                 \
union __name##_sring_entry {                                            \
    typeof ((__params)->req) req;                                       \
    typeof ((__params)->rsp) rsp;                                       \
} PACKED;                                                               \
                                                                        \
/* Shared ring page */                                                  \
struct __name##_sring {                                                 \
    RING_IDX req_prod;                                                  \
    RING_IDX rsp_prod;                                                  \
    union __name##_sring_entry                                          \
        ring[__SRING_SIZE(__params, sizeof (union __name##_sring_entry))];        \
} PACKED;                                                               \
                                                                        \
/* "Front" end's private variables */                                   \
struct __name##_front_ring {                                            \
    RING_IDX req_prod_pvt;                                              \
    RING_IDX rsp_cons;                                                  \
    struct __name##_sring *sring;                                       \
};                                                                      \
                                                                        \
/* "Back" end's private variables */                                    \
struct __name##_back_ring {                                             \
    RING_IDX rsp_prod_pvt;                                              \
    RING_IDX req_cons;                                                  \
    struct __name##_sring *sring;                                       \
};                                                                      \
                                                                        \
/* Syntactic sugar */                                                   \
typedef struct __name##_sring __name##_sring_t;                         \
typedef struct __name##_front_ring __name##_front_ring_t;               \
typedef struct __name##_back_ring __name##_back_ring_t;

/*
 *   Macros for manipulating rings.  
 * 
 *   FRONT_RING_whatever works on the "front end" of a ring: here 
 *   requests are pushed on to the ring and responses taken off it.
 * 
 *   BACK_RING_whatever works on the "back end" of a ring: here 
 *   requests are taken off the ring and responses put on.
 * 
 *   N.B. these macros do NO INTERLOCKS OR FLOW CONTROL.  
 *   This is OK in 1-for-1 request-response situations where the 
 *   requestor (front end) never has more than SRING_SIZE()-1
 *   outstanding requests.
 */


/* Initialising empty rings */
#define SHARED_RING_INIT(_p, _s) do {                                   \
    (_s)->req_prod = 0;                                                 \
    (_s)->rsp_prod = 0;                                                 \
} while(0)

#define FRONT_RING_INIT(_p, _r, _s) do {                                \
    (_r)->req_prod_pvt = 0;                                             \
    (_r)->rsp_cons = 0;                                                 \
    (_r)->sring = (_s);                                                 \
} while (0)

#define BACK_RING_INIT(_p, _r, _s) do {                                 \
    (_r)->rsp_prod_pvt = 0;                                             \
    (_r)->req_cons = 0;                                                 \
    (_r)->sring = (_s);                                                 \
} while (0)

/* Initialize to existing shared indexes -- for recovery */
#define FRONT_RING_ATTACH(_p, _r, _s) do {                              \
    (_r)->sring = (_s);                                                 \
    (_r)->req_prod_pvt = (_s)->req_prod;                                \
    (_r)->rsp_cons = (_s)->rsp_prod;                                    \
} while (0)

#define BACK_RING_ATTACH(_p, _r, _s) do {                               \
    (_r)->sring = (_s);                                                 \
    (_r)->rsp_prod_pvt = (_s)->rsp_prod;                                \
    (_r)->req_cons = (_s)->req_prod;                                    \
} while (0)


/* How to mask off a number for use as an offset into a ring 
 * N.B. This evalutes its second argument once but its first often */
#define __SHARED_RING_MASK(_p, _s, _i)                                  \
    ((_i) & (SRING_SIZE((_p), (_s)) - 1))

/* How big is this ring? */
#define RING_SIZE(_p, _r) SRING_SIZE((_p), (_r)->sring)

/* How many empty slots are on a ring? */
#define RING_PENDING_REQUESTS(_p, _r)                                   \
   ( ((_r)->req_prod_pvt - (_r)->rsp_cons) )
   
/* Test if there is an empty slot available on the front ring. 
 * (This is only meaningful from the front. )
 */
#define RING_FULL(_p, _r)                                               \
    (((_r)->req_prod_pvt - (_r)->rsp_cons) == SRING_SIZE((_p), (_r)->sring))

/* Test if there are outstanding messages to be processed on a ring. */
#define RING_HAS_UNCONSUMED_RESPONSES(_p, _r)                           \
   ( (_r)->rsp_cons != (_r)->sring->rsp_prod )
   
#define RING_HAS_UNCONSUMED_REQUESTS(_p, _r)                            \
   ( ((_r)->req_cons != (_r)->sring->req_prod ) &&                      \
     (((_r)->req_cons - (_r)->rsp_prod_pvt) !=                          \
      SRING_SIZE((_p), (_r)->sring)) )
      
/* Test if there are messages waiting to be pushed. */
#define RING_HAS_UNPUSHED_REQUESTS(_p, _r)                              \
   ( (_r)->req_prod_pvt != (_r)->sring->req_prod )
   
#define RING_HAS_UNPUSHED_RESPONSES(_p, _r)                             \
   ( (_r)->rsp_prod_pvt != (_r)->sring->rsp_prod )
   

/* Copy the private producer pointer into the shared ring so the other end 
 * can see the updates we've made. */
#define RING_PUSH_REQUESTS(_p, _r) do {                                 \
    wmb();                                                              \
    (_r)->sring->req_prod = (_r)->req_prod_pvt;                         \
} while (0)

#define RING_PUSH_RESPONSES(_p, _r) do {                                \
    wmb();                                                              \
    (_r)->sring->rsp_prod = (_r)->rsp_prod_pvt;                         \
} while (0)

/* Direct access to individual ring elements, by index.  
 */
#define RING_GET_REQUEST(_p, _r, _idx)                                  \
 (&((_r)->sring->ring[                                                  \
     __SHARED_RING_MASK((_p), (_r)->sring, (_idx))                      \
     ].req))

#define RING_GET_RESPONSE(_p, _r, _idx)                                 \
 (&((_r)->sring->ring[                                                  \
     __SHARED_RING_MASK((_p), (_r)->sring, (_idx))                      \
     ].rsp))   
    
/* Loop termination condition: Would the specified index overflow the 
 * ring? 
 */
#define RING_REQUEST_CONS_OVERFLOW(_p, _r, _cons)                      \
    (((_cons) - (_r)->rsp_prod_pvt) >= SRING_SIZE((_p), (_r)->sring))

#endif /* __XEN_PUBLIC_IO_RING_H__ */
