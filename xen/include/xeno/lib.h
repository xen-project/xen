#ifndef __LIB_H__
#define __LIB_H__

#include <stdarg.h>
#include <xeno/types.h>

#ifndef NDEBUG
#define ASSERT(_p) if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s", #_p , __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif

#define reserve_bootmem(_p,_l) \
printk("Memory Reservation 0x%lx, %lu bytes\n", (_p), (_l))

/* lib.c */
#include <xeno/string.h>

/* JWS - pulled over linux string library ({asm,linux}/string.h)
int memcmp(const void * cs,const void * ct,size_t count);
void * memcpy(void * dest,const void *src,size_t count);
int strncmp(const char * cs,const char * ct,size_t count);
int strcmp(const char * cs,const char * ct);
char * strcpy(char * dest,const char *src);
char * strncpy(char * dest,const char *src,size_t count);
void * memset(void * s,int c,size_t count);
size_t strnlen(const char * s, size_t count);
size_t strlen(const char * s);
char * strchr(const char *,int);
char * strstr(const char * s1,const char * s2);
*/

unsigned long str_to_quad(unsigned char *s);
unsigned char *quad_to_str(unsigned long q, unsigned char *s);

/* kernel.c */
#define printk printf
void printf (const char *format, ...);
void cls(void);
void panic(const char *format, ...);

/* vsprintf.c */
extern int sprintf(char * buf, const char * fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
extern int vsprintf(char *buf, const char *, va_list);
extern int snprintf(char * buf, size_t size, const char * fmt, ...)
	__attribute__ ((format (printf, 3, 4)));
extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);

long simple_strtol(const char *cp,char **endp,unsigned int base);
unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base);
long long simple_strtoll(const char *cp,char **endp,unsigned int base);

/* Produce a 32-bit hash from a key string 'k' of length 'len' bytes. */
unsigned long hash(unsigned char *k, unsigned long len);

#endif /* __LIB_H__ */
