/**************************************************************************
 * 
 * parallax-threaded.h
 *
 * a few thread-specific defines
 *
 */
 
#ifndef __PARALLAX_THREADED_H__
#define __PARALLAX_THREADED_H__
 
#if 0
/* Turn off threading. */
#define NOTHREADS
#endif

#define READ_POOL_SIZE 128

/* per-thread identifier */
pthread_key_t tid_key;

#endif /* __PARALLAX_THREADED_H__ */

