#ifndef _POSIX_PTHREAD_H
#define _POSIX_PTHREAD_H

/* Let's be single-threaded for now.  */

typedef void *pthread_key_t;
typedef struct {} pthread_mutex_t, pthread_once_t;
#define PTHREAD_MUTEX_INITIALIZER {}
#define PTHREAD_ONCE_INIT {}
static inline int pthread_mutex_lock(pthread_mutex_t *mutex) { return 0; }
static inline int pthread_mutex_unlock(pthread_mutex_t *mutex) { return 0; }
static inline int pthread_key_create(pthread_key_t *key, void (*destr_function)(void*)) { *key = NULL; return 0; }
static inline int pthread_setspecific(pthread_key_t *key, const void *pointer) { *key = (void*) pointer; return 0; }
static inline void *pthread_getspecific(pthread_key_t *key) { return *key; }
static inline int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) { init_routine(); return 0; }

#define __thread

#endif /* _POSIX_PTHREAD_H */
