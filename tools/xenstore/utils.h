#ifndef _UTILS_H
#define _UTILS_H
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

/* Is A == B ? */
#define streq(a,b) (strcmp((a),(b)) == 0)

/* Does A start with B ? */
#define strstarts(a,b) (strncmp((a),(b),strlen(b)) == 0)

/* Does A end in B ? */
static inline bool strends(const char *a, const char *b)
{
	if (strlen(a) < strlen(b))
		return false;

	return streq(a + strlen(a) - strlen(b), b);
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define ___stringify(x)	#x
#define __stringify(x)		___stringify(x)

/* Convenient wrappers for malloc and realloc.  Use them. */
#define new(type) ((type *)malloc_nofail(sizeof(type)))
#define new_array(type, num) realloc_array((type *)0, (num))
#define realloc_array(ptr, num) ((__typeof__(ptr))_realloc_array((ptr), sizeof((*ptr)), (num)))

void *malloc_nofail(size_t size);
void *realloc_nofail(void *ptr, size_t size);
void *_realloc_array(void *ptr, size_t size, size_t num);

void barf(const char *fmt, ...) __attribute__((noreturn));
void barf_perror(const char *fmt, ...) __attribute__((noreturn));

/* This version adds one byte (for nul term) */
void *grab_file(const char *filename, unsigned long *size);
void release_file(void *data, unsigned long size);

/* For writing daemons, based on Stevens. */
void daemonize(void);

/* Signal handling: returns fd to listen on. */
int signal_to_fd(int signal);
void close_signal(int fd);

void xprintf(const char *fmt, ...);

#define eprintf(_fmt, _args...) xprintf("[ERR] %s" _fmt, __FUNCTION__, ##_args)
#define iprintf(_fmt, _args...) xprintf("[INF] %s" _fmt, __FUNCTION__, ##_args)

#ifdef DEBUG
#define dprintf(_fmt, _args...) xprintf("[DBG] %s" _fmt, __FUNCTION__, ##_args)
#else
#define dprintf(_fmt, _args...) ((void)0)
#endif

#endif /* _UTILS_H */
